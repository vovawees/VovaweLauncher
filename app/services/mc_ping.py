import asyncio
import json
import struct
import time
from app.core.security import now_ts
from app.services.cache import McStatus, RuntimeCache


def _pack_varint(val: int) -> bytes:
    out = bytearray()
    while True:
        byte = val & 0x7F
        val >>= 7
        if val != 0:
            byte |= 0x80
        out.append(byte)
        if val == 0:
            break
    return bytes(out)


async def _read_varint(reader: asyncio.StreamReader) -> int:
    num = 0
    for i in range(5):
        b = await reader.readexactly(1)
        val = b[0]
        num |= (val & 0x7F) << (7 * i)
        if not (val & 0x80):
            return num
    raise ValueError("VarInt too big")


async def ping_mc_server(host: str, port: int, maintenance: bool) -> McStatus:
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.5)
        try:
            host_b = host.encode("utf-8")
            handshake_data = (
                b"\x00"
                + _pack_varint(763)  # MC 1.20.1 protocol
                + _pack_varint(len(host_b))
                + host_b
                + struct.pack(">H", port)
                + _pack_varint(1)
            )
            writer.write(_pack_varint(len(handshake_data)) + handshake_data)
            writer.write(b"\x01\x00")
            await writer.drain()

            _ = await asyncio.wait_for(_read_varint(reader), timeout=2.5)  # packet len
            pkt_id = await asyncio.wait_for(_read_varint(reader), timeout=2.5)
            if pkt_id != 0:
                raise ValueError("Unexpected packet id")

            str_len = await asyncio.wait_for(_read_varint(reader), timeout=2.5)
            payload = await asyncio.wait_for(reader.readexactly(str_len), timeout=2.5)
            data = json.loads(payload.decode("utf-8"))

            ping_ms = max(1, int((time.perf_counter() - start) * 1000))
            players = data.get("players", {})
            desc = data.get("description", "Dead Mile '96")
            motd = desc.get("text", "Dead Mile '96") if isinstance(desc, dict) else str(desc)

            return McStatus(
                online=not maintenance,
                players_online=int(players.get("online", 0)),
                players_max=int(players.get("max", 200)),
                motd=motd,
                version=str(data.get("version", {}).get("name", "1.20.1")),
                ping_ms=ping_ms,
                maintenance=maintenance,
                updated_at=now_ts(),
            )
        finally:
            writer.close()
            await writer.wait_closed()
    except Exception:
        return McStatus(
            online=False,
            players_online=0,
            players_max=200,
            motd="Сервер недоступен",
            version="1.20.1",
            ping_ms=0,
            maintenance=maintenance,
            updated_at=now_ts(),
        )


async def mc_ping_loop(cache: RuntimeCache, host: str, port: int, interval: float, maintenance: bool) -> None:
    while True:
        cache.mc_status = await ping_mc_server(host, port, maintenance)
        await asyncio.sleep(interval)
