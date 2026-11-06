"""Minimal Modbus TCP: frame codec, async server, async client.

Supports the function codes real HMIs/PLCs use for process values:
  3  Read Holding Registers   (setpoints, commands)
  4  Read Input Registers     (sensor readings)
  6  Write Single Register
  16 Write Multiple Registers
Modbus has no authentication: anyone who can reach port 502 can write. That's
the gap the guard closes.
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from typing import Awaitable, Callable

READ_HOLDING, READ_INPUT, WRITE_SINGLE, WRITE_MULTIPLE = 3, 4, 6, 16
ILLEGAL_FUNCTION, ILLEGAL_ADDRESS, ILLEGAL_VALUE, DEVICE_FAILURE = 1, 2, 3, 4


class ModbusError(Exception):
    def __init__(self, code: int):
        super().__init__(f"Modbus exception {code}")
        self.code = code


@dataclass
class Request:
    tid: int
    unit: int
    fc: int
    address: int = 0
    count: int = 0
    values: list[int] | None = None

    @property
    def is_write(self) -> bool:
        return self.fc in (WRITE_SINGLE, WRITE_MULTIPLE)


async def read_frame(reader: asyncio.StreamReader) -> tuple[int, int, bytes]:
    head = await reader.readexactly(7)
    tid, proto, length, unit = struct.unpack(">HHHB", head)
    if proto != 0 or not 2 <= length <= 254:
        raise ConnectionError("not a Modbus TCP frame")
    pdu = await reader.readexactly(length - 1)
    return tid, unit, pdu


def frame(tid: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def parse_request(tid: int, unit: int, pdu: bytes) -> Request:
    fc = pdu[0]
    if fc in (READ_HOLDING, READ_INPUT):
        addr, count = struct.unpack(">HH", pdu[1:5])
        if not 1 <= count <= 125:
            raise ModbusError(ILLEGAL_VALUE)
        return Request(tid, unit, fc, addr, count)
    if fc == WRITE_SINGLE:
        addr, val = struct.unpack(">HH", pdu[1:5])
        return Request(tid, unit, fc, addr, 1, [val])
    if fc == WRITE_MULTIPLE:
        addr, count, nbytes = struct.unpack(">HHB", pdu[1:6])
        if nbytes != 2 * count or not 1 <= count <= 123:
            raise ModbusError(ILLEGAL_VALUE)
        vals = list(struct.unpack(f">{count}H", pdu[6:6 + nbytes]))
        return Request(tid, unit, fc, addr, count, vals)
    raise ModbusError(ILLEGAL_FUNCTION)


def build_request(req: Request) -> bytes:
    if req.fc in (READ_HOLDING, READ_INPUT):
        pdu = struct.pack(">BHH", req.fc, req.address, req.count)
    elif req.fc == WRITE_SINGLE:
        pdu = struct.pack(">BHH", req.fc, req.address, req.values[0])
    else:
        n = len(req.values)
        pdu = struct.pack(f">BHHB{n}H", req.fc, req.address, n, 2 * n, *req.values)
    return frame(req.tid, req.unit, pdu)


def response_pdu(req: Request, values: list[int] | None = None) -> bytes:
    if req.fc in (READ_HOLDING, READ_INPUT):
        return struct.pack(f">BB{len(values)}H", req.fc, 2 * len(values), *values)
    if req.fc == WRITE_SINGLE:
        return struct.pack(">BHH", req.fc, req.address, req.values[0])
    return struct.pack(">BHH", req.fc, req.address, req.count)


def exception_pdu(fc: int, code: int) -> bytes:
    return bytes([fc | 0x80, code])


Handler = Callable[[Request, tuple], Awaitable[bytes]]


async def serve(handler: Handler, host: str, port: int) -> asyncio.base_events.Server:
    """Generic Modbus TCP server: handler(request, peer) -> response PDU."""

    async def on_client(reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            while True:
                tid, unit, pdu = await read_frame(reader)
                try:
                    req = parse_request(tid, unit, pdu)
                    out = await handler(req, peer)
                except ModbusError as e:
                    out = exception_pdu(pdu[0], e.code)
                writer.write(frame(tid, unit, out))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(on_client, host, port)


class Client:
    """Tiny async Modbus TCP client (one request in flight at a time)."""

    def __init__(self, host: str, port: int, unit: int = 1):
        self.host, self.port, self.unit = host, port, unit
        self._tid = 0
        self._lock = asyncio.Lock()
        self.reader = self.writer = None

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        return self

    async def close(self):
        if self.writer:
            self.writer.close()

    async def _call(self, req: Request) -> bytes:
        async with self._lock:
            if self.writer is None:
                await self.connect()
            self._tid = (self._tid + 1) & 0xFFFF
            req.tid = self._tid
            self.writer.write(build_request(req))
            await self.writer.drain()
            _, _, pdu = await read_frame(self.reader)
        if pdu[0] & 0x80:
            raise ModbusError(pdu[1])
        return pdu

    async def read_holding(self, address: int, count: int) -> list[int]:
        pdu = await self._call(Request(0, self.unit, READ_HOLDING, address, count))
        return list(struct.unpack(f">{count}H", pdu[2:2 + 2 * count]))

    async def read_input(self, address: int, count: int) -> list[int]:
        pdu = await self._call(Request(0, self.unit, READ_INPUT, address, count))
        return list(struct.unpack(f">{count}H", pdu[2:2 + 2 * count]))

    async def write(self, address: int, value: int):
        await self._call(Request(0, self.unit, WRITE_SINGLE, address, 1, [value]))

    async def write_many(self, address: int, values: list[int]):
        await self._call(Request(0, self.unit, WRITE_MULTIPLE, address, len(values), values))
