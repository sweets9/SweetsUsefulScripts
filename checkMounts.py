#!/usr/bin/env python3
"""
checkMounts.py – Network Share Monitoring/Repair Script
Version: 1.2.0
Author: exJuice
Last Modified: 2025-07-19
License: MIT

Description:
------------
This script monitors and repairs NFS/SMB network shares defined in /etc/fstab.
It checks mount health, handles stale mounts, unmounts and remounts as needed,
and sends alerts to syslog and optionally via email.

Features:
---------
- Parses /etc/fstab and filters only NFS/SMB mounts.
- Detects stale handles and missing sentinel file (.checkMount).
- Attempts multi-stage unmount (soft, force, lazy) and remounts.
- Detects and warns about residual files left in mountpoints.
- Logs to syslog and can send admin alerts by email.
- Summary email at end of script if issues are found.
- Loads config from `.env` file if present (non-critical override).

Usage:
------
  python3 checkMounts.py           # Normal run
  python3 checkMounts.py --debug   # Debug mode with full email output
  python3 checkMounts.py --install # Install to root's crontab
  python3 checkMounts.py --remove  # Remove from root's crontab

Requirements:
-------------
- Python 3.8+
- Place variables into .env file if required

Tested Platforms:
-----------------
- Ubuntu 22.04+, Debian 12+, Fedora 40+

Change Log:
-----------
v1.2.0 - 2025-07-19
  • Added support for .env-based configuration overrides
  • Changed notifications to send a single summary email per run

v1.1.0 - 2024-11-10
  • Added residual file detection and folder size reporting
  • Improved remount retry logic
  • Enhanced syslog logging and debug mode output

v1.0.0 - 2024-10-01
  • Initial version with basic NFS/SMB health checks
  • Stale mount detection and automatic repair logic
  • Optional syslog and email notifications
"""

import os
from dotenv import load_dotenv
from pathlib import Path

# Load .env if available
env_path = Path(__file__).with_name(".env")
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

def getenv(key, default=None, cast=None):
    val = os.getenv(key, default)
    if cast is bool:
        return val.lower() in ("1", "true", "yes", "on") if isinstance(val, str) else bool(val)
    if cast is int:
        return int(val)
    if cast is list:
        return [x.strip() for x in val.split(",")]
    return val

# ─────────────── CONFIG ────────────────
SEND_NOTIFICATIONS = getenv("SEND_NOTIFICATIONS", "true", bool)
EMAIL_SERVER = getenv("EMAIL_SERVER", "mail")
EMAIL_PORT   = getenv("EMAIL_PORT", 25, int)
EMAIL_FROM   = getenv("EMAIL_FROM", "noreply@example.com")
EMAIL_TO     = getenv("EMAIL_TO", "admin@example.com", list)

NOTIFY = {
    "share_down"     : True,
    "stale_handle"   : True,
    "residual_files" : True,
    "remount_result" : True,
    "script_errors"  : True,
    "debug_output"   : False,
}

# Used for batching
email_queue = []

SLEEP = 2.0
MAX_LISTING = 20
MAX_RETRIES = 3
SENTINEL_FILE = ".checkMount"
# ────────────────────────────────────────────────────────────────────────────

import re
import sys
import errno
import time
import syslog
import argparse
import subprocess
import smtplib
from email.message import EmailMessage
from datetime import datetime
from pathlib import Path
from typing import List, Tuple
from io import StringIO

start_time = None
debug_output = StringIO()
original_stdout = sys.stdout
original_stderr = sys.stderr

class TeeOutput:
    def __init__(self, original, buffer):
        self.original = original
        self.buffer = buffer

    def write(self, text):
        self.original.write(text)
        self.buffer.write(text)
        return len(text)

    def flush(self):
        self.original.flush()
        self.buffer.flush()

def setup_logging(debug_mode=False):
    global debug_output, start_time
    start_time = datetime.now()
    syslog.openlog("checkMount", syslog.LOG_PID, syslog.LOG_DAEMON)
    if debug_mode:
        NOTIFY["debug_output"] = True
        sys.stdout = TeeOutput(original_stdout, debug_output)
        sys.stderr = TeeOutput(original_stderr, debug_output)

def log(msg: str, level: int = syslog.LOG_INFO):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}")
    syslog.syslog(level, msg)

def send_email(subject: str, body: str, notify_key: str = None):
    if not SEND_NOTIFICATIONS:
        return
    if notify_key and not NOTIFY.get(notify_key, True):
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    email_queue.append((subject, body, timestamp))


def parse_fstab() -> List[Tuple[str, str, str]]:
    wanted = {"nfs", "nfs4", "cifs", "smbfs"}
    entries: List[Tuple[str, str, str]] = []

    try:
        with open("/etc/fstab", encoding="utf-8") as fh:
            for line_num, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = re.split(r"\s+", line)
                if len(parts) < 3:
                    log(f"WARNING: Invalid fstab line {line_num}: {line}", syslog.LOG_WARNING)
                    continue
                device, mountpoint, fstype = parts[:3]
                if fstype.lower() in wanted:
                    if not os.path.exists(mountpoint):
                        log(f"WARNING: Mountpoint {mountpoint} does not exist", syslog.LOG_WARNING)
                        try:
                            os.makedirs(mountpoint, mode=0o755, exist_ok=True)
                            log(f"Created mountpoint directory: {mountpoint}")
                        except OSError as exc:
                            log(f"ERROR: Could not create mountpoint {mountpoint}: {exc}", syslog.LOG_ERR)
                            continue
                    entries.append((device, mountpoint, fstype.lower()))
    except FileNotFoundError:
        log("ERROR: /etc/fstab not found", syslog.LOG_ERR)
        return []
    except Exception as exc:
        log(f"ERROR parsing /etc/fstab: {exc}", syslog.LOG_ERR)
        return []

    return entries

def mounted_points() -> set[str]:
    try:
        with open("/proc/mounts", encoding="utf-8") as fh:
            return {line.split()[1] for line in fh if len(line.split()) >= 2}
    except Exception:
        try:
            out = subprocess.check_output(["mount"], text=True, encoding="utf-8", timeout=10)
            return {re.search(r" on (\S+) type", line).group(1) for line in out.splitlines() if re.search(r" on (\S+) type", line)}
        except Exception as exc:
            log(f"ERROR getting mounted points: {exc}", syslog.LOG_ERR)
            return set()


def is_stale(mountpoint: str) -> Tuple[bool, str]:
    try:
        path = Path(mountpoint)
        if not path.exists():
            return True, "mountpoint does not exist"
        try:
            next(path.iterdir())
        except StopIteration:
            pass
        except OSError as exc:
            if exc.errno in (errno.ESTALE, errno.EIO, errno.ENOTCONN, errno.ENOENT):
                return True, os.strerror(exc.errno)
    except Exception as exc:
        log(f"Unexpected error checking {mountpoint}: {exc}", syslog.LOG_WARNING)
    sentinel = Path(mountpoint, SENTINEL_FILE)
    if not sentinel.is_file():
        return True, f"{SENTINEL_FILE} file missing"
    return False, "healthy"

def unmount_with_retry(mountpoint: str) -> bool:
    """Try to unmount a mountpoint (soft, force, lazy) with retries."""
    if mountpoint not in mounted_points():
        return True

    try:
        result = subprocess.run(["umount", mountpoint], capture_output=True, timeout=30, text=True)
        if result.returncode == 0:
            time.sleep(SLEEP)
            if mountpoint not in mounted_points():
                log(f"Soft unmount successful: {mountpoint}")
                return True
        else:
            log(f"Soft unmount failed: {mountpoint} - {result.stderr.strip()}")
    except Exception as exc:
        log(f"Soft unmount failed: {mountpoint}: {exc}", syslog.LOG_WARNING)

    log(f"Attempting force unmount: {mountpoint}")
    try:
        result = subprocess.run(["umount", "-f", mountpoint], capture_output=True, timeout=30, text=True)
        time.sleep(SLEEP)
        if mountpoint not in mounted_points():
            log(f"Force unmount successful: {mountpoint}")
            return True
        else:
            log(f"Force unmount failed: {mountpoint} - {result.stderr.strip()}")
    except Exception as exc:
        log(f"Force unmount failed: {mountpoint}: {exc}", syslog.LOG_WARNING)

    log(f"Attempting lazy unmount: {mountpoint}")
    try:
        result = subprocess.run(["umount", "-l", mountpoint], capture_output=True, timeout=30, text=True)
        time.sleep(SLEEP * 2)
        if mountpoint not in mounted_points():
            log(f"Lazy unmount successful: {mountpoint}")
            return True
        else:
            log(f"Lazy unmount failed: {mountpoint} - {result.stderr.strip()}")
    except Exception as exc:
        log(f"Lazy unmount failed: {mountpoint}: {exc}", syslog.LOG_ERR)

    return False


def remount_with_retry(mountpoint: str) -> bool:
    """Try mounting the mountpoint with retries."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = subprocess.run(["mount", mountpoint], capture_output=True, timeout=60, text=True)
            time.sleep(SLEEP)
            if mountpoint in mounted_points():
                log(f"Mount successful on attempt {attempt}: {mountpoint}")
                return True
            else:
                log(f"Mount attempt {attempt} failed: {mountpoint}")
                if result.stderr:
                    log(f"Mount stderr: {result.stderr.strip()}")
        except Exception as exc:
            log(f"Mount attempt {attempt} error: {mountpoint}: {exc}", syslog.LOG_WARNING)

        if attempt < MAX_RETRIES:
            time.sleep(SLEEP * attempt)  # exponential backoff

    return False


def format_size(size_bytes: int) -> str:
    """Format bytes into human-readable format."""
    if size_bytes == 0:
        return "0 B"

    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    size = float(size_bytes)
    unit_index = 0

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    else:
        return f"{size:.2f} {units[unit_index]}"

def get_folder_size_fast(path: Path) -> int:
    """Calculate total folder size efficiently, excluding sentinel file."""
    total_size = 0
    try:
        for item in path.rglob('*'):
            if item.name == SENTINEL_FILE:
                continue
            try:
                if item.is_file():
                    total_size += item.stat().st_size
            except (OSError, IOError):
                continue
    except Exception:
        pass
    return total_size

def get_residual_files(mountpoint: str) -> List[Path]:
    """Return a list of files/folders left after unmount, ignoring sentinel file."""
    leftover = []
    try:
        path = Path(mountpoint)
        if path.exists() and path.is_dir():
            for entry in path.iterdir():
                if entry.name != SENTINEL_FILE:
                    leftover.append(entry)
                    if len(leftover) >= MAX_LISTING:
                        break

            # If we found residual files, show details and warning
            if leftover:
                # Show list of files/folders (top 10)
                file_list = [entry.name for entry in leftover[:10]]
                log(f"Residual files/folders: {', '.join(file_list)}")

                # Show "..." if truncated
                if len(leftover) >= MAX_LISTING:
                    log("...")

                # Calculate and show total folder size
                total_size = get_folder_size_fast(path)
                formatted_size = format_size(total_size)
                log(f"Total folder size: {formatted_size}")

                # Show warning
                log("Warning: residual files appear to have been written when mount was offline.", syslog.LOG_WARNING)

    except Exception as exc:
        log(f"Error checking residual files in {mountpoint}: {exc}", syslog.LOG_WARNING)
    return leftover

def handle_share(device: str, mountpoint: str, fstype: str) -> None:
    """Check and fix one share mount point."""
    log(f"Processing {device} -> {mountpoint} ({fstype})")

    mnt_set = mounted_points()
    mounted = mountpoint in mnt_set
    needs_remount = False

    if not mounted:
        log(f"{mountpoint} is not mounted.")
        if NOTIFY["share_down"]:
            send_email(f"Share DOWN: {mountpoint}",
                       f"The {fstype.upper()} share {device} at {mountpoint} is not mounted.",
                       "share_down")
        needs_remount = True
    else:
        is_stale_result, stale_reason = is_stale(mountpoint)
        if is_stale_result:
            log(f"Stale mount detected at {mountpoint}: {stale_reason}")
            if NOTIFY["stale_handle"]:
                send_email(f"Stale handle: {mountpoint}",
                           f"Stale handle detected at {mountpoint}.\nReason: {stale_reason}\nDevice: {device}",
                           "stale_handle")
            if not unmount_with_retry(mountpoint):
                log(f"ERROR: Failed to unmount stale share: {mountpoint}", syslog.LOG_ERR)
                send_email(f"Unmount FAILED: {mountpoint}",
                           f"Failed to unmount stale share {mountpoint} ({device})",
                           "script_errors")
                return
            needs_remount = True

    if needs_remount:
        leftover = get_residual_files(mountpoint)
        if leftover and NOTIFY["residual_files"]:
            body = (f"After unmounting {mountpoint} we found {len(leftover)} file(s)/folder(s):\n\n"
                    + "\n".join(f"  {p}" for p in leftover[:MAX_LISTING]))
            if len(leftover) > MAX_LISTING:
                body += f"\n... and {len(leftover) - MAX_LISTING} more items"
            send_email(f"Residual files: {mountpoint}", body, "residual_files")

        mount_success = remount_with_retry(mountpoint)

        if mount_success:
            time.sleep(SLEEP)  # let mount settle
            is_stale_after, stale_reason = is_stale(mountpoint)

            # Special case: remount worked but sentinel still missing
            if is_stale_after and stale_reason == f"{SENTINEL_FILE} file missing":
                log(f"Remount succeeded but sentinel file '{SENTINEL_FILE}' is missing at {mountpoint}", syslog.LOG_WARNING)
                send_email(f"Sentinel missing after remount: {mountpoint}",
                           f"Share {device} at {mountpoint} was successfully remounted, "
                           f"but the required sentinel file '{SENTINEL_FILE}' is still missing.\n\n"
                           f"Consider verifying the share contents.",
                           "script_errors")
                mount_success = True  # Do NOT treat as a failure
            elif is_stale_after:
                log(f"Remount failed due to persistent stale state at {mountpoint}", syslog.LOG_ERR)
                mount_success = False

        if NOTIFY["remount_result"]:
            status = "OK" if mount_success else "FAILED"
            send_email(f"Remount {status}: {mountpoint}",
                       f"Share {device} at {mountpoint} remount {'successful' if mount_success else 'FAILED'}.",
                       "remount_result")

    else:
        log(f"No remount needed for {mountpoint}")


def install_to_crontab():
    """Add the script to root's crontab if not already present."""
    script_path = os.path.abspath(__file__)
    cron_line = f"*/5 * * * * /usr/bin/python3 {script_path} >/dev/null 2>&1"

    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        current_cron = result.stdout if result.returncode == 0 else ""

        if "checkMounts.py" in current_cron:
            print("checkMounts.py already installed in crontab:")
            for line in current_cron.splitlines():
                if "checkMounts.py" in line:
                    print(f"  {line}")
            return

        new_cron = current_cron + f"\n# Network share monitoring\n{cron_line}\n"
        proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
        proc.communicate(input=new_cron)

        if proc.returncode == 0:
            print("Successfully installed checkMounts.py to root's crontab.")
            print(f"Schedule: Every 5 minutes")
            print(f"Command: {cron_line}")
        else:
            print("Failed to install to crontab.")

    except Exception as exc:
        print(f"Error installing to crontab: {exc}")


def remove_from_crontab():
    """Remove the script's entries from root's crontab."""
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if result.returncode != 0:
            print("No crontab for root or unable to read.")
            return
        lines = result.stdout.splitlines()
        new_lines = [line for line in lines if "checkMounts.py" not in line]

        if len(new_lines) == len(lines):
            print("No checkMounts.py entry found in crontab.")
            return

        new_cron = "\n".join(new_lines) + "\n"
        proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
        proc.communicate(input=new_cron)

        if proc.returncode == 0:
            print("Removed checkMounts.py from root's crontab.")
        else:
            print("Failed to remove from crontab.")
    except Exception as exc:
        print(f"Error removing from crontab: {exc}")


def cleanup_and_exit(exit_code: int = 0):
    global start_time, debug_output

    end_time = datetime.now()
    runtime = end_time - start_time
    log(f"Script completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"Total runtime: {runtime.total_seconds():.2f} seconds")

    if email_queue:
        try:
            hostname = subprocess.getoutput("hostname -f") or subprocess.getoutput("hostname")
        except:
            hostname = "unknown"

        msg = EmailMessage()
        msg["Subject"] = f"[checkMount] {hostname} Summary Report"
        msg["From"] = EMAIL_FROM
        msg["To"] = ", ".join(EMAIL_TO)

        body_lines = []
        for subj, body, ts in email_queue:
            body_lines.append(f"\n--- {subj} ---\nTime: {ts}\n{body}\n")
        msg.set_content("\n".join(body_lines))

        try:
            with smtplib.SMTP(EMAIL_SERVER, EMAIL_PORT, timeout=30) as smtp:
                smtp.send_message(msg)
            log("Summary email sent.")
        except Exception as exc:
            log(f"ERROR sending summary email: {exc}", syslog.LOG_ERR)

    if NOTIFY.get("debug_output", False):
        debug_content = debug_output.getvalue()
        if debug_content:
            send_email("Debug Output", f"Complete script output:\n\n{debug_content}", "debug_output")

    sys.stdout = original_stdout
    sys.stderr = original_stderr
    syslog.closelog()
    sys.exit(exit_code)


def main():
    parser = argparse.ArgumentParser(description="Network Share Monitor")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode (emails full output)")
    parser.add_argument("--install", action="store_true", help="Install script to root's crontab")
    parser.add_argument("--remove", "-r", action="store_true", help="Remove script from root's crontab")
    args = parser.parse_args()

    if args.install:
        if os.geteuid() != 0:
            print("ERROR: Must run as root to install to crontab")
            print("Try: sudo python3 checkMounts.py --install")
            sys.exit(1)
        install_to_crontab()
        return

    if args.remove:
        if os.geteuid() != 0:
            print("ERROR: Must run as root to remove from crontab")
            print("Try: sudo python3 checkMounts.py --remove")
            sys.exit(1)
        remove_from_crontab()
        return

    setup_logging(args.debug)
    log("Starting checkMounts.py")
    log(f"Script started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    if os.geteuid() != 0:
        log("WARNING: Not running as root. Mount operations may fail.", syslog.LOG_WARNING)

    entries = parse_fstab()
    if not entries:
        log("No NFS/SMB entries found in /etc/fstab. Exiting.")
        cleanup_and_exit(0)

    log(f"Found {len(entries)} network shares to check")

    errors = []
    for device, mountpoint, fstype in entries:
        log(f"--- Processing {mountpoint} ({fstype}) ---")
        try:
            handle_share(device, mountpoint, fstype)
        except Exception as exc:
            err = f"Unhandled error for {mountpoint}: {exc}"
            log(err, syslog.LOG_ERR)
            errors.append(err)

    if errors and NOTIFY.get("script_errors", True):
        send_email("Script execution errors",
                   f"checkMounts.py encountered {len(errors)} error(s):\n\n" + "\n".join(f"  - {e}" for e in errors),
                   "script_errors")

    cleanup_and_exit(1 if errors else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Script interrupted by user", syslog.LOG_INFO)
        cleanup_and_exit(1)
    except Exception as exc:
        log(f"Fatal error: {exc}", syslog.LOG_ERR)
        cleanup_and_exit(1)
