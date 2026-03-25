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

PATH = ""
server_instance = None
server_task = None

async def run_cpp_scanner(websocket):
    try:
        process = await asyncio.create_subprocess_exec(
            "./scanner",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        print("[+] Scanner started")

        while True:
            line = await process.stdout.readline()
            if not line:
                print("not line")
                break

            decoded = line.decode().strip()
            print("[CPP]", decoded)

            if "program complete" in decoded:
                print("[+] Detected scan completion from C++")
                break

        # 🔥 ADD THIS
        stderr = await process.stderr.read()
        if stderr:
            print("[CPP ERROR]", stderr.decode())

        await process.wait()
        print("[+] Scan finished")

        await websocket.send(json.dumps({
            "event": "SCAN_COMPLETE"
        }))

    except Exception as e:
        print(f"[!] Scanner error: {e}")

async def handle_message(message,websocket):
    try:
        data = json.loads(message)
        event = data.get("event")

        print(f"[+] Event received: {event}")

        if event == "START_SCAN":
            print("[*] Starting scan...")
            # trigger your C++ scanner or logic
            asyncio.create_task(run_cpp_scanner(websocket))

        elif event == "STOP_SCAN":
            print("[*] Stopping scan...")

        elif event == "DELETE_FILE":
            file_id = data.get("file_id")
            print(f"[*] Delete file request: {file_id}")

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
                await start_socket_server(websocket)
                await asyncio.sleep(0.5)
                while True:
                    message = await websocket.recv()
                    print("[+] Received:", message)
                    await handle_message(message,websocket)

        except Exception as e:
            print(f"[!] Connection error: {e}")
            print("[*] Shutting down socket server...")

            global server_instance

            if server_instance is not None:
                server_instance.close()
                await server_instance.wait_closed()
                server_instance = None
                print("[+] Socket server closed")

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
    global server_instance

    if server_instance is not None:
        print("[!] Server already running, skipping...")
        return

    server_instance = await asyncio.start_server(
        lambda r, w: handle_client(r, w, websocket),
        "127.0.0.1",
        9000
    )

    print("[+] Socket server started on port 9000")

    # ✅ DO NOT block here
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
    print("🔥🔥🔥 HANDLE CLIENT TRIGGERED 🔥🔥🔥")
    try:
        while True:
            data = await read_exact(reader, 8)
            if not data:
                break

            type_, value = struct.unpack('!if', data)  # ! = network order
            print("PROGRESSSSSSSSSSSSSSSSS", value)
            await websocket.send(json.dumps({
                "event": "SCAN_PROGRESS",
                "value": value
            }))

    except Exception as e:
        print(f"[!] Client error: {e}")

    finally:
        writer.close()
        await writer.wait_closed()
        print("[-] C++ client disconnected")
if __name__ == "__main__":
    asyncio.run(connect())