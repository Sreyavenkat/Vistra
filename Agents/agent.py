import asyncio
import websockets
import json
import uuid
import struct
def get_device_id():
    try:
        with open("/etc/machine-id", "r") as f:
            return f.read().strip()
    except:
        return None

SERVER_URL = "ws://localhost:8000/ws/agent"
DEVICE_ID = get_device_id()

async def handle_message(message):
    try:
        data = json.loads(message)
        print(f"[+] Received command: {data}")
    except Exception as e:
        print(f"[!] Error parsing message: {e}")


async def connect():
    url = f"{SERVER_URL}/{DEVICE_ID}"

    while True:
        try:
            print(f"[*] Connecting to {url}...")

            async with websockets.connect(url) as websocket:
                print("[+] Connected to backend")
                asyncio.create_task(heartbeat(websocket))
                asyncio.create_task(start_socket_server(websocket))
                while True:
                    message = await websocket.recv()
                    print("[+] Received:", message)

        except Exception as e:
            print(f"[!] Connection error: {e}")
            print("[*] Reconnecting in 5 seconds...")
            await asyncio.sleep(5)

async def heartbeat(websocket):
    while True:
        await websocket.send(json.dumps({
            "event": "ping"
        }))
        print("pinging backend......")
        await asyncio.sleep(5)
async def start_socket_server(websocket):
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, websocket),
        "127.0.0.1",
        9000
    )

    print("[+] Socket server started on port 9000")

    async with server:
        await server.serve_forever()
async def read_exact(reader, n):
    data = b''
    while len(data) < n:
        chunk = await reader.read(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data
async def handle_client(reader, writer, websocket):
    addr = writer.get_extra_info('peername')
    print(f"[+] C++ client connected: {addr}")

    try:
        while True:
            data = await read_exact(reader, 8)
            if not data:
                break

            type_, value = struct.unpack('!if', data)  # ! = network order
            print(type_, value)

    except Exception as e:
        print(f"[!] Client error: {e}")

    finally:
        writer.close()
        await writer.wait_closed()
        print("[-] C++ client disconnected")
if __name__ == "__main__":
    asyncio.run(connect())