"""Modbus TCP from scratch: frame codec, async server, async client.

Function codes handled (the ones HMIs and PLCs use for process data):
   1 Read Coils                    5 Write Single Coil
   2 Read Discrete Inputs         15 Write Multiple Coils
   3 Read Holding Registers        6 Write Single Register
   4 Read Input Registers         16 Write Multiple Registers
  22 Mask Write Register          23 Read/Write Multiple Registers

22 and 23 matter for security: they *write* registers but don't look like the
"normal" write codes, so a filter that only inspects 6 and 16 can be bypassed
with them. Everything else (diagnostics 8, device ID 43, vendor codes like
Schneider UMAS 90...) is parsed as an opaque `unknown` request so a gateway can
decide what to do with it (Aegis blocks and logs it).

Modbus has no authentication: anyone who can reach port 502 can write. That's
the gap the guard closes.
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Awaitable, Callable

READ_COILS, READ_DISCRETE, READ_HOLDING, READ_INPUT = 1, 2, 3, 4
WRITE_COIL, WRITE_SINGLE, WRITE_COILS, WRITE_MULTIPLE = 5, 6, 15, 16
MASK_WRITE, READ_WRITE = 22, 23
KNOWN = {1, 2, 3, 4, 5, 6, 15, 16, 22, 23}
WRITE_FCS = {5, 6, 15, 16, 22, 23}
COIL_FCS = {1, 2, 5, 15}

ILLEGAL_FUNCTION, ILLEGAL_ADDRESS, ILLEGAL_VALUE, DEVICE_FAILURE = 1, 2, 3, 4
GATEWAY_PATH_UNAVAILABLE, GATEWAY_TARGET_FAILED = 0x0A, 0x0B

FC_NAMES = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers", 4: "Read Input Registers",
    5: "Write Single Coil", 6: "Write Single Register", 7: "Read Exception Status",
    8: "Diagnostics (can force the PLC into listen-only mode or restart comms)",
    11: "Get Comm Event Counter", 12: "Get Comm Event Log", 15: "Write Multiple Coils",
    16: "Write Multiple Registers", 17: "Report Server ID", 20: "Read File Record", 21: "Write File Record",
    22: "Mask Write Register", 23: "Read/Write Multiple Registers", 24: "Read FIFO Queue",
    43: "Encapsulated Interface / Read Device Identification (reconnaissance)",
    90: "Schneider UMAS (vendor: program download, start/stop PLC)",
}


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
    values: list[int] | None = None          # register values, or 0/1 for coils
    and_mask: int = 0                        # FC 22
    or_mask: int = 0                         # FC 22
    read_address: int = 0                    # FC 23
    read_count: int = 0                      # FC 23
    raw: bytes = field(default=b"", repr=False)   # original PDU

    @property
    def is_write(self) -> bool:
        return self.fc in WRITE_FCS

    @property
    def known(self) -> bool:
        return self.fc in KNOWN

    @property
    def table(self) -> str:
        """Which data table a write targets: 'coil' or 'holding'."""
        return "coil" if self.fc in COIL_FCS else "holding"


# ------------------------------------------------------------------ framing
async def read_frame(reader: asyncio.StreamReader) -> tuple[int, int, bytes]:
    head = await reader.readexactly(7)
    tid, proto, length, unit = struct.unpack(">HHHB", head)
    if proto != 0 or not 2 <= length <= 254:
        raise ConnectionError("not a Modbus TCP frame")
    pdu = await reader.readexactly(length - 1)
    return tid, unit, pdu


def frame(tid: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def pack_bits(bits: list[int]) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def unpack_bits(data: bytes, count: int) -> list[int]:
    return [(data[i // 8] >> (i % 8)) & 1 for i in range(count)]


def _parse(tid: int, unit: int, pdu: bytes) -> Request:
    fc = pdu[0]
    if fc in (READ_COILS, READ_DISCRETE):
        addr, count = struct.unpack(">HH", pdu[1:5])
        if not 1 <= count <= 2000:
            raise ModbusError(ILLEGAL_VALUE)
        return Request(tid, unit, fc, addr, count, raw=pdu)
    if fc in (READ_HOLDING, READ_INPUT):
        addr, count = struct.unpack(">HH", pdu[1:5])
        if not 1 <= count <= 125:
            raise ModbusError(ILLEGAL_VALUE)
        return Request(tid, unit, fc, addr, count, raw=pdu)
    if fc == WRITE_COIL:
        addr, val = struct.unpack(">HH", pdu[1:5])
        if val not in (0x0000, 0xFF00):
            raise ModbusError(ILLEGAL_VALUE)
        return Request(tid, unit, fc, addr, 1, [1 if val else 0], raw=pdu)
    if fc == WRITE_SINGLE:
        addr, val = struct.unpack(">HH", pdu[1:5])
        return Request(tid, unit, fc, addr, 1, [val], raw=pdu)
    if fc == WRITE_COILS:
        addr, count, nbytes = struct.unpack(">HHB", pdu[1:6])
        if not 1 <= count <= 1968 or nbytes != (count + 7) // 8 or len(pdu) < 6 + nbytes:
            raise ModbusError(ILLEGAL_VALUE)
        return Request(tid, unit, fc, addr, count, unpack_bits(pdu[6:6 + nbytes], count), raw=pdu)
    if fc == WRITE_MULTIPLE:
        addr, count, nbytes = struct.unpack(">HHB", pdu[1:6])
        if nbytes != 2 * count or not 1 <= count <= 123 or len(pdu) < 6 + nbytes:
            raise ModbusError(ILLEGAL_VALUE)
        vals = list(struct.unpack(f">{count}H", pdu[6:6 + nbytes]))
        return Request(tid, unit, fc, addr, count, vals, raw=pdu)
    if fc == MASK_WRITE:
        addr, and_m, or_m = struct.unpack(">HHH", pdu[1:7])
        return Request(tid, unit, fc, addr, 1, None, and_m, or_m, raw=pdu)
    if fc == READ_WRITE:
        raddr, rcount, waddr, wcount, nbytes = struct.unpack(">HHHHB", pdu[1:10])
        if not 1 <= rcount <= 125 or not 1 <= wcount <= 121 or nbytes != 2 * wcount or len(pdu) < 10 + nbytes:
            raise ModbusError(ILLEGAL_VALUE)
        vals = list(struct.unpack(f">{wcount}H", pdu[10:10 + nbytes]))
        return Request(tid, unit, fc, waddr, wcount, vals, read_address=raddr, read_count=rcount, raw=pdu)
    return Request(tid, unit, fc, raw=pdu)        # unknown: caller decides


def parse_request(tid: int, unit: int, pdu: bytes) -> Request:
    """Never raises anything but ModbusError, whatever bytes arrive."""
    if not pdu:
        raise ModbusError(ILLEGAL_FUNCTION)
    try:
        return _parse(tid, unit, pdu)
    except ModbusError:
        raise
    except (struct.error, IndexError, ValueError):
        raise ModbusError(ILLEGAL_VALUE)


def mask_result(current: int, and_mask: int, or_mask: int) -> int:
    """Modbus spec: result = (current AND and_mask) OR (or_mask AND NOT and_mask)."""
    return (current & and_mask) | (or_mask & (~and_mask & 0xFFFF))


def build_pdu(req: Request) -> bytes:
    fc = req.fc
    if fc in (READ_COILS, READ_DISCRETE, READ_HOLDING, READ_INPUT):
        return struct.pack(">BHH", fc, req.address, req.count)
    if fc == WRITE_COIL:
        return struct.pack(">BHH", fc, req.address, 0xFF00 if req.values[0] else 0)
    if fc == WRITE_SINGLE:
        return struct.pack(">BHH", fc, req.address, req.values[0])
    if fc == WRITE_COILS:
        data = pack_bits(req.values)
        return struct.pack(">BHHB", fc, req.address, len(req.values), len(data)) + data
    if fc == WRITE_MULTIPLE:
        n = len(req.values)
        return struct.pack(f">BHHB{n}H", fc, req.address, n, 2 * n, *req.values)
    if fc == MASK_WRITE:
        return struct.pack(">BHHH", fc, req.address, req.and_mask, req.or_mask)
    if fc == READ_WRITE:
        n = len(req.values)
        return struct.pack(f">BHHHHB{n}H", fc, req.read_address, req.read_count, req.address, n, 2 * n,
                           *req.values)
    return req.raw


def build_request(req: Request) -> bytes:
    return frame(req.tid, req.unit, build_pdu(req))


def response_pdu(req: Request, values: list[int] | None = None) -> bytes:
    fc = req.fc
    if fc in (READ_HOLDING, READ_INPUT, READ_WRITE):
        return struct.pack(f">BB{len(values)}H", fc, 2 * len(values), *values)
    if fc in (READ_COILS, READ_DISCRETE):
        data = pack_bits(values)
        return struct.pack(">BB", fc, len(data)) + data
    if fc in (WRITE_SINGLE, WRITE_COIL, MASK_WRITE):
        return req.raw[:7] if fc == MASK_WRITE else req.raw[:5]
    return struct.pack(">BHH", fc, req.address, req.count)   # 15, 16


def exception_pdu(fc: int, code: int) -> bytes:
    return bytes([(fc | 0x80) & 0xFF, code])


Handler = Callable[[Request, tuple], Awaitable[bytes]]


async def serve(handler: Handler, host: str, port: int, idle_timeout: float = 120.0,
                max_clients: int = 64) -> asyncio.base_events.Server:
    """Generic Modbus TCP server: handler(request, peer) -> response PDU.

    Idle connections are dropped after `idle_timeout` seconds and at most
    `max_clients` connections are served at once, so one misbehaving client
    can't exhaust the device (a real problem for small embedded PLCs).
    """
    active = {"n": 0}

    async def on_client(reader, writer):
        peer = writer.get_extra_info("peername")
        if active["n"] >= max_clients:
            writer.close()
            return
        active["n"] += 1
        try:
            while True:
                tid, unit, pdu = await asyncio.wait_for(read_frame(reader), idle_timeout)
                try:
                    req = parse_request(tid, unit, pdu)
                    out = await handler(req, peer)
                except ModbusError as e:
                    out = exception_pdu(pdu[0] if pdu else 0, e.code)
                except Exception:     # a handler bug must never kill the server
                    out = exception_pdu(pdu[0] if pdu else 0, DEVICE_FAILURE)
                writer.write(frame(tid, unit, out))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError, OSError):
            pass
        finally:
            active["n"] -= 1
            writer.close()

    return await asyncio.start_server(on_client, host, port)


class Client:
    """Small async Modbus TCP client (one request in flight at a time).

    Reconnects automatically on the next call if the connection dropped.
    """

    def __init__(self, host: str, port: int, unit: int = 1, timeout: float = 5.0, local_ip: str | None = None):
        self.host, self.port, self.unit, self.timeout = host, port, unit, timeout
        self.local_ip = local_ip     # bind to a specific source address (demo attackers use 127.0.0.66)
        self._tid = 0
        self._lock = asyncio.Lock()
        self.reader = self.writer = None

    async def connect(self):
        if self.local_ip:
            try:
                self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(
                    self.host, self.port, local_addr=(self.local_ip, 0)), self.timeout)
                return self
            except OSError:
                pass     # OS doesn't allow that source address: fall back to the default
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port), self.timeout)
        return self

    async def close(self):
        if self.writer:
            self.writer.close()
            self.writer = None

    async def call_pdu(self, pdu: bytes, unit: int | None = None) -> bytes:
        """Send a raw PDU, return the raw response PDU (raises ModbusError on exception replies)."""
        async with self._lock:
            try:
                if self.writer is None:
                    await self.connect()
                self._tid = (self._tid + 1) & 0xFFFF
                self.writer.write(frame(self._tid, self.unit if unit is None else unit, pdu))
                await self.writer.drain()
                _, _, out = await asyncio.wait_for(read_frame(self.reader), self.timeout)
            except (OSError, ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError):
                self.writer = None
                raise ConnectionError(f"no response from {self.host}:{self.port}")
        if out[0] & 0x80:
            raise ModbusError(out[1])
        return out

    async def _call(self, req: Request) -> bytes:
        return await self.call_pdu(build_pdu(req))

    async def read_holding(self, address: int, count: int) -> list[int]:
        pdu = await self._call(Request(0, self.unit, READ_HOLDING, address, count))
        return list(struct.unpack(f">{count}H", pdu[2:2 + 2 * count]))

    async def read_input(self, address: int, count: int) -> list[int]:
        pdu = await self._call(Request(0, self.unit, READ_INPUT, address, count))
        return list(struct.unpack(f">{count}H", pdu[2:2 + 2 * count]))

    async def read_coils(self, address: int, count: int) -> list[int]:
        pdu = await self._call(Request(0, self.unit, READ_COILS, address, count))
        return unpack_bits(pdu[2:], count)

    async def read_discrete(self, address: int, count: int) -> list[int]:
        pdu = await self._call(Request(0, self.unit, READ_DISCRETE, address, count))
        return unpack_bits(pdu[2:], count)

    async def write(self, address: int, value: int):
        await self._call(Request(0, self.unit, WRITE_SINGLE, address, 1, [value]))

    async def write_many(self, address: int, values: list[int]):
        await self._call(Request(0, self.unit, WRITE_MULTIPLE, address, len(values), values))

    async def write_coil(self, address: int, value: int):
        await self._call(Request(0, self.unit, WRITE_COIL, address, 1, [1 if value else 0]))

    async def write_coils(self, address: int, values: list[int]):
        await self._call(Request(0, self.unit, WRITE_COILS, address, len(values), values))

    async def mask_write(self, address: int, and_mask: int, or_mask: int):
        await self._call(Request(0, self.unit, MASK_WRITE, address, 1, None, and_mask, or_mask))

    async def read_write(self, read_address: int, read_count: int, address: int, values: list[int]) -> list[int]:
        pdu = await self._call(Request(0, self.unit, READ_WRITE, address, len(values), values,
                                       read_address=read_address, read_count=read_count))
        return list(struct.unpack(f">{read_count}H", pdu[2:2 + 2 * read_count]))

    async def write_tag(self, tag, value: float):
        """Write an engineering value to a tag (coil or holding register)."""
        if tag.table == "coil":
            await self.write_coil(tag.address, 1 if value else 0)
        else:
            await self.write(tag.address, max(0, min(65535, tag.to_raw(value))))
