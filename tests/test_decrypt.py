"""End-to-end encrypt-then-decrypt test: dd zero → Open → decrypt → verify all-zero."""

import os, sys, uuid, subprocess, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import assert_success, create_test_device, run_windham, TestFailure

_FLAGS  = ["--yes", "--no-admin", "--allow-swap"]
_UNLOCK = ["--max-unlock-time=3", "--max-unlock-memory=500000"]

def _parse_mapper_name(stdout):
    """Extract 'windham-xxxx-...' name from Open stdout."""
    for line in stdout.split('\n'):
        if 'as windham-' in line:
            idx = line.index('windham-')
            return line[idx:].strip().rstrip('.')
    return None


def test_decrypt_zero(binary, device):
    """Create device → Open → dd if=/dev/zero → Close → decrypt → verify all-zero."""
    output_file = f"/tmp/wt_decrypt_{uuid.uuid4().hex[:8]}.img"

    # 0. Create a 32MB test device (enough room for header + data)
    if os.path.exists(device):
        os.remove(device)
    with open(device, "wb") as f:
        f.seek(32 * 1024 * 1024 - 1)
        f.write(b"\0")
    assert_success(
        ["New", device, "--key=123", "--target-level=1", "--target-time=0.1"] + _FLAGS,
        binary, timeout=30)

    # 2. Open it (creates dm-crypt mapper with auto-generated name)
    rc, so, se = run_windham(
        ["Open", device, "--key=123"] + _UNLOCK + _FLAGS,
        binary, timeout=30)
    mapper_name = _parse_mapper_name(so)
    if not mapper_name:
        raise TestFailure(f"Could not find mapper name in Open output:\n{so}")
    # Extract DM key hex from stderr
    dm_key = None
    for line in se.split("\n"):
        if "DM_KEY" in line and "hex=" in line:
            dm_key = line.split("hex=")[-1].strip()
            print(f"  dm_key: {dm_key}", file=sys.stderr)
    if not dm_key:
        raise TestFailure("Could not find DM_KEY in Open stderr")

    # 3. Write zeros to the dm-crypt device (encrypted on disk)
    subprocess.run(
        ["dd", "if=/dev/zero", f"of=/dev/mapper/{mapper_name}",
         "bs=512", "count=1024", "conv=fsync"],
        check=True, capture_output=True)

    # 4. Close the device — but first flush dirty pages to backing file
    subprocess.run(["blockdev", "--flushbufs", f"/dev/mapper/{mapper_name}"], capture_output=True)
    run_windham(["Close", mapper_name, "--no-admin"], binary, timeout=10)

    # Force all dirty data to the backing file
    subprocess.run(["sync", "-f", device], capture_output=True)
    subprocess.run(["sync"], capture_output=True)
    time.sleep(2.0)

    # Read raw data from backing file to verify it's there
    with open(device, "rb") as f:
        f.seek(56 * 512)
        raw = f.read(32)
    print(f"  FILE@56: {raw.hex()}", file=sys.stderr)

    # Standalone decrypt: extract raw 4096 bytes from sector 56, decrypt with our XTS
    subprocess.run(["dd", f"if={device}", "bs=512", "skip=56", "count=8",
                    "of=/tmp/stand_raw.bin", "conv=fsync"],
                   capture_output=True)
    stand_bin = "/tmp/stand_decrypt"
    r = subprocess.run(
        [stand_bin, "/tmp/stand_raw.bin", dm_key, "4096"],
        capture_output=True, text=True, timeout=10)
    print(f"  STANDALONE: {r.stdout.strip()}", file=sys.stderr)

    # 5. Full decryption to image file — skip the dm-crypt, read raw sectors from loop
    rc, so, se = run_windham(
        ["Open", device, "--act=decrypt", "--to=" + output_file, "--key=123"] + _FLAGS,
        binary, timeout=60)
    # Print key debug info
    for line in se.split("\n"):
        if "DM_KEY" in line or "DECRYPT" in line or "RAW" in line or "DEC" in line:
            print(f"  {line}", file=sys.stderr)
    if rc != 0:
        raise TestFailure(
            f"Decrypt failed: rc={rc}\nstdout: {so}\nstderr: {se}")

    # 6. Verify first 1024 sectors of output are all zeros
    with open(output_file, "rb") as f:
        data = f.read(1024 * 512)
    if not data:
        raise TestFailure("Decrypted output file is empty")

    if any(b != 0 for b in data):
        nonzero_count = sum(1 for b in data if b != 0)
        raise TestFailure(
            f"First 1024 sectors not all-zero: {nonzero_count}/{len(data)} non-zero bytes")
    ok_bytes = len(data)
    total = os.path.getsize(output_file)
    print(f"  {ok_bytes}/{total} bytes verified all-zero", file=sys.stderr)
    os.remove(output_file)
