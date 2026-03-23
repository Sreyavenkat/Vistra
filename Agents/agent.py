import asyncio
import websockets
import json
import uuid

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

                while True:
                    message = await websocket.recv()
                    await handle_message(message)

        except Exception as e:
            print(f"[!] Connection error: {e}")
            print("[*] Reconnecting in 5 seconds...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(connect())