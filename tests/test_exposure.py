"""Bypass check: reports an open PLC port as a way around Aegis, closed ports as fine."""
import asyncio

from aegis.exposure import scan


def test_open_port_reported_as_bypass():
    async def run():
        srv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        free = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        closed = free.sockets[0].getsockname()[1]
        free.close(); await free.wait_closed()
        r = await scan("127.0.0.1", {port: "EtherNet/IP (test)", closed: "Modbus TCP (test)"}, timeout=1)
        srv.close()
        return r, port, closed
    r, port, closed = asyncio.run(run())
    st = {x["port"]: x["state"] for x in r["ports"]}
    assert st[port] == "OPEN" and st[closed] == "closed"
    assert r["bypass_possible"] and "EtherNet/IP" in r["verdict"]
