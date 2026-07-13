"""Test --create-exfat: New with --create-exfat, Open, verify exFAT filesystem."""

import os, sys, subprocess, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import create_test_device, run_windham, TestFailure

_FLAGS  = ["--yes", "--no-admin", "--allow-swap"]
_UNLOCK = ["--max-unlock-time=3", "--max-unlock-memory=500000"]


def test_create_exfat(binary, device):
    """New --create-exfat → Open → verify exFAT superblock via dm-crypt mapper."""
    if os.path.exists(device):
        os.remove(device)
    with open(device, "wb") as f:
        f.seek(32 * 1024 * 1024 - 1)
        f.write(b"\0")

    # 1. New with --create-exfat
    rc, so, se = run_windham(
        ["New", device, "--key=123", "--target-level=1",
         "--target-time=0.1", "--create-exfat"] + _FLAGS,
        binary, timeout=60)
    if rc != 0:
        raise TestFailure(f"New --create-exfat failed: rc={rc}\nstderr: {se}")

    # 2. Open (creates dm-crypt mapper)
    mapper_name = "windham-exfat-test"
    rc, so, se = run_windham(
        ["Open", device, "--key=123", "--to=" + mapper_name] + _UNLOCK + _FLAGS,
        binary, timeout=30)
    if rc != 0:
        raise TestFailure(f"Open failed: rc={rc}\nstderr: {se}")

    # 3. Wait for dm-crypt to settle
    time.sleep(2.0)

    # 4. Read exFAT superblock via dm-crypt mapper
    mapper_path = f"/dev/mapper/{mapper_name}"
    with open(mapper_path, "rb") as f:
        header = f.read(512)

    sig = header[3:11]
    print(f"  sig@3: {sig.hex()}", file=sys.stderr)

    if sig == b"EXFAT   ":
        print(f"  exFAT signature verified", file=sys.stderr)
    else:
        # Show raw file data for debugging
        with open(device, "rb") as f:
            f.seek(56 * 512)
            raw = f.read(32)
        print(f"  raw@56: {raw.hex()}", file=sys.stderr)
        raise TestFailure(
            f"exFAT not found: sig={sig.hex()}, raw={raw.hex()}")

    # 5. Cleanup
    run_windham(["Close", mapper_name, "--no-admin"], binary, timeout=10)
