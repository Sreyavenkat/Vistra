
import os
import time
import json
import uuid
from datetime import datetime

LOG_FILE = "Layer2/syscall_queue.log"
ALERT_DIR = "alerts"
RISK_THRESHOLD = 70

BURST_WINDOW_SECONDS = 3
PROFILE_EXPIRY_SECONDS = 30


# -----------------------------------------
# Process Profile
# -----------------------------------------
class ProcessProfile:
    def __init__(self, pid, ppid, comm):
        self.pid = pid
        self.ppid = ppid
        self.comm = comm

        self.first_seen = time.time()
        self.last_seen = time.time()

        self.exec_path = None

        self.open_count = 0
        self.read_bytes = 0
        self.write_bytes = 0
        self.rename_count = 0
        self.unlink_count = 0

        self.files_touched = set()
        self.renamed_files = []
        self.deleted_files = []

        self.syscall_timestamps = []

        self.risk_score = 0
        self.alerted = False

    def update_activity(self):
        now = time.time()
        self.last_seen = now
        self.syscall_timestamps.append(now)

        # Cleanup old timestamps
        self.syscall_timestamps = [
            t for t in self.syscall_timestamps
            if now - t < BURST_WINDOW_SECONDS
        ]


# -----------------------------------------
# Risk Scoring
# -----------------------------------------
def calculate_risk(profile):
    score = 0

    # Rename burst (ransomware behavior)
    if profile.rename_count > 20:
        score += 50

    # Mass deletion
    if profile.unlink_count > 20:
        score += 40

    # Heavy file writes
    if profile.write_bytes > 10 * 1024 * 1024:
        score += 30

    # Burst syscall activity
    if len(profile.syscall_timestamps) > 50:
        score += 30

    # Suspicious execution location
    if profile.exec_path:
        if profile.exec_path.startswith("/tmp") \
           or profile.exec_path.startswith("/dev/shm") \
           or profile.exec_path.startswith("/var/tmp"):
            score += 30

    return score


# -----------------------------------------
# Alert Writer (Atomic)
# -----------------------------------------
def write_alert(profile):
    os.makedirs(ALERT_DIR, exist_ok=True)

    alert_data = {
        "alert_id": str(uuid.uuid4()),
        "detected_at": datetime.utcnow().isoformat() + "Z",
        "classification": {
            "label": "MALICIOUS",
            "risk_score": profile.risk_score,
            "confidence": "HIGH"
        },
        "process": {
            "pid": profile.pid,
            "ppid": profile.ppid,
            "comm": profile.comm,
            "exec_path": profile.exec_path,
            "first_seen": datetime.utcfromtimestamp(profile.first_seen).isoformat() + "Z",
            "last_seen": datetime.utcfromtimestamp(profile.last_seen).isoformat() + "Z",
            "runtime_seconds": profile.last_seen - profile.first_seen
        },
        "behavior_summary": {
            "rename_count": profile.rename_count,
            "unlink_count": profile.unlink_count,
            "write_bytes": profile.write_bytes,
            "burst_syscalls": len(profile.syscall_timestamps)
        },
        "file_activity": {
            "renamed_files": profile.renamed_files,
            "deleted_files": profile.deleted_files
        },
        "status": "PENDING"
    }

    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    filename = f"{timestamp}_{profile.pid}_{alert_data['alert_id']}.json"

    final_path = os.path.join(ALERT_DIR, filename)
    tmp_path = final_path + ".tmp"

    with open(tmp_path, "w") as f:
        json.dump(alert_data, f, indent=4)

    os.replace(tmp_path, final_path)

    print(f"[ALERT] Malicious process detected → PID {profile.pid}")


# -----------------------------------------
# Log Parser
# -----------------------------------------
def parse_line(line):
    parts = line.strip().split(" | ")
    data = {}

    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            data[key] = value

    return data


# -----------------------------------------
# Layer-2 Engine
# -----------------------------------------
def run():
    process_table = {}

    print("[+] Layer-2 Engine running...")
    OWN_PID = str(os.getpid())
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()

            #if line:
                # print("[DEBUG] RAW LINE:", line.strip())
            if not line:
                time.sleep(0.2)
                continue

            data = parse_line(line)
            if data.get("PID") == OWN_PID:
                continue
            # Ignore stdout/stderr writes
            if data.get("FD") in ["1", "2"]:
                continue

            # Ignore processes without real file path
            if not data.get("PATH"):
                continue
            if "PID" not in data:
                continue

            pid = int(data["PID"])
            ppid = int(data["PPID"])
            comm = data["COMM"]
            syscall = data["SYSCALL"]

            if pid not in process_table:
                process_table[pid] = ProcessProfile(pid, ppid, comm)

            profile = process_table[pid]
            profile.update_activity()

            # -------------------------
            # Update behavior
            # -------------------------

            if syscall == "execve":
                profile.exec_path = data.get("PATH")

            elif syscall == "openat":
                profile.open_count += 1
                if "PATH" in data:
                    profile.files_touched.add(data["PATH"])

            elif syscall == "read":
                profile.read_bytes += int(data.get("COUNT", 0))

            elif syscall == "write":
                profile.write_bytes += int(data.get("COUNT", 0))

            elif syscall == "renameat":
                profile.rename_count += 1
                profile.renamed_files.append({
                    "old_path": data.get("PATH"),
                    "new_path": data.get("NEW_PATH")
                })

            elif syscall == "unlinkat":
                profile.unlink_count += 1
                profile.deleted_files.append(data.get("PATH"))

            elif syscall == "exit":
                # Optional: remove profile immediately
                pass

            # -------------------------
            # Recalculate Risk
            # -------------------------
            profile.risk_score = calculate_risk(profile)

            if profile.risk_score >= RISK_THRESHOLD and not profile.alerted:
                write_alert(profile)
                profile.alerted = True

            # -------------------------
            # Cleanup expired profiles
            # -------------------------
            now = time.time()
            expired_pids = [
                p for p, prof in process_table.items()
                if now - prof.last_seen > PROFILE_EXPIRY_SECONDS
            ]

            for p in expired_pids:
                del process_table[p]


if __name__ == "__main__":
    run()