import asyncio
import websockets
import json
import uuid
import struct
import os
import stat
import shutil
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

current_scan_id = None
current_device_id = None
def restore_original_permissions(quarantinePath):
    meta_path = quarantinePath + ".meta"

    if not os.path.exists(meta_path):
        print("[!] No metadata found")
        return

    try:
        with open(meta_path, "r") as f:
            mode = int(f.read())

        os.chmod(quarantinePath, mode)
        print(f"[+] Restored original permissions for: {quarantinePath}")

    except Exception as e:
        print(f"[!] Failed to restore permissions: {e}")

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
            "event": "SCAN_COMPLETED",
            "scan_id": current_scan_id,

        }))

    except Exception as e:
        print(f"[!] Scanner error: {e}")

async def handle_message(message,websocket):
    try:
        data = json.loads(message)
        event = data.get("event")

        print(f"[+] Event received: {event}")

        if event in ["START_SCAN", "SCAN_START"]:
            global current_scan_id
            global current_device_id
            current_scan_id = data.get("scan_id")
            current_device_id = data.get("device_id")
            print(f"[+] Event received: START_SCAN")

            await websocket.send(json.dumps({
                "event": "START_SCAN",
                "scan_id": current_scan_id,
                "device_id": current_device_id
            }))
            print("[*] Starting scan...")
            # trigger your C++ scanner or logic
            asyncio.create_task(run_cpp_scanner(websocket))

        elif event == "STOP_SCAN":
            print("[*] Stopping scan...")

        elif event == "DELETE_FILE":
            scanId = data.get("scanId")
            file_name = data.get("fileName")
            file_path = data.get("filePath")
            # 🔥 Build full file path
            full_path = os.path.join(file_path, file_name)

            print(f"[*] Delete file request: {scanId, file_name, full_path}")

            try:
                # ✅ Check if file exists
                if os.path.exists(full_path):
                    os.remove(full_path)
                    print(f"[+] File deleted: {full_path}")

                    response = {
                        "status": "success",
                        "message": f"{file_name} deleted"
                    }
                else:
                    print(f"[!] File not found: {full_path}")

                    response = {
                        "status": "error",
                        "message": "File not found"
                    }
                
            except Exception as e:
                print(f"[!] Error deleting file: {e}")

                response = {
                    "status": "error",
                    "message": str(e)
                }
        elif event == "KEEP_FILE":
            scanId = data.get("scanId")
            file_name = data.get("fileName")
            file_path = data.get("filePath")
            
            # 🔥 Original location
            full_path = os.path.join(file_path, file_name)

            quarantinePath = data.get("quarantinePath")
            full_quarantine_path = os.path.join(quarantinePath, file_name)

            print(f"[*] Keep file request: {scanId, file_name, full_path, full_quarantine_path}")

            try:
                print("[+] Full quarantine path",full_quarantine_path)
                if os.path.exists(full_quarantine_path):

                    os.makedirs(file_path, exist_ok=True)

                    # 1. Move file
                    shutil.move(full_quarantine_path, full_path)

                    print(f"[+] File restored to original location: {full_path}")

                    # 2. Set permissions (same as your C++ chmod)
                    os.chmod(full_path, 0o600)
                    print(f"[+] Permissions set to 600 for: {full_path}")

                    response = {
                        "status": "success",
                        "message": f"{file_name} restored successfully"
                        }               
                else:
                    print(f"[!] File not found in quarantine: {full_quarantine_path}")

                    response = {
                        "status": "error",
                        "message": "File not found in quarantine"
                    }

            except Exception as e:
                print(f"[!] Error restoring file: {e}")

                response = {
                    "status": "error",
                    "message": str(e)
                }
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
        #print("pinging backend......")
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

    try:
        while True:
            data = await read_exact(reader, 4)
            if not data:
                break

            # Try reading as old frame
            (type,) = struct.unpack('!i', data)

             # 🟢 CASE 1: FRAME (type + float)
            if type != 999 and type != 1001:
                rest = await read_exact(reader, 4)
                if not rest:
                    break

                (value,) = struct.unpack('!f', rest)

                print("PROGRESS:", value, type)

                if type == 1:
                    await websocket.send(json.dumps({
                        "event": "SCAN_COMPLETED",
                        "scan_id": current_scan_id,
                        "value": value,
                        "type": type
                    }))
                else:
                    await websocket.send(json.dumps({
                        "event": "SCAN_PROGRESS",
                        "value": value
                    }))

            # 🔴 CASE 2: COMPLETION (4 more ints)
            elif type == 999:
                rest = await read_exact(reader, 16)
                if not rest:
                    break
                totalThreats, quarantine, deletion, safe = struct.unpack('!iiii', rest)

                print("📊 COMPLETION:")
                print(totalThreats, quarantine, deletion, safe)

                await websocket.send(json.dumps({
                    "event": "FILE_COUNT",
                    "value": {
                        "totalThreats": totalThreats,
                        "quarantine": quarantine,
                        "deletion": deletion,
                        "safe": safe
                    }
                }))
                await websocket.send(json.dumps({
                    "event": "FILE_RESULT",
                    "scan_id": current_scan_id,
                    "value": {
                        "totalThreats": totalThreats,
                        "quarantine": quarantine,
                        "deletion": deletion,
                        "safe": safe
                    }
                }))

            elif type == 1001:
                # 🔵 FILES BATCH (NEW)

                # read length
                length_data = await read_exact(reader, 4)
                if not length_data:
                    break

                (length,) = struct.unpack('!i', length_data)

                # read JSON
                json_data = await read_exact(reader, length)
                if not json_data:
                    break

                message = json.loads(json_data.decode())

                print("📂 FILES_BATCH RECEIVED")

                await websocket.send(json.dumps({
                    "event": "FILES_BATCH",
                    "scan_id": current_scan_id,
                    "files": message.get("files", [])
                }))
                                

    except Exception as e:
        print(f"[!] Client error: {e}")

    finally:
        writer.close()
        await writer.wait_closed()
        print("[-] C++ client disconnected")
if __name__ == "__main__":
    asyncio.run(connect())