import asyncio
import socket
from uuid import UUID

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

UID = UUID("86f7d2f9-f9d8-40be-9a70-f5427d0ac5a5").bytes

app = FastAPI()


@app.get("/")
async def index():
    return {"status": "ok"}


@app.websocket("/ws")
async def vless(ws: WebSocket):
    await ws.accept()
    writer = None
    try:
        d = await ws.receive_bytes()
        if d[1:17] != UID:
            return await ws.close()
        i = 18 + d[17]
        if d[i] != 1:  # TCP only
            return await ws.close()
        port = int.from_bytes(d[i + 1:i + 3], "big")
        i += 3
        t = d[i]
        i += 1
        if t == 1:
            host = socket.inet_ntoa(d[i:i + 4])
            i += 4
        elif t == 2:
            n = d[i]
            host = d[i + 1:i + 1 + n].decode()
            i += 1 + n
        elif t == 3:
            host = socket.inet_ntop(socket.AF_INET6, d[i:i + 16])
            i += 16
        else:
            return await ws.close()

        reader, writer = await asyncio.open_connection(host, port)
        writer.write(d[i:])
        await writer.drain()
        await ws.send_bytes(b"\x00\x00")

        async def up():
            while True:
                writer.write(await ws.receive_bytes())
                await writer.drain()

        async def down():
            while True:
                b = await reader.read(16384)
                if not b:
                    break
                await ws.send_bytes(b)

        tasks = [asyncio.create_task(up()), asyncio.create_task(down())]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for x in tasks:
            x.cancel()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        if writer:
            writer.close()
