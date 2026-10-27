"""Comprehensive parameter tests for New/Open/AddKey/DelKey."""

REQUIRES = "any"  # test block: isoc | gnu-linux | any
import os, sys, uuid, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import run_windham, assert_success, assert_error, create_test_device

F  = ["--yes", "--no-admin"]
_O = lambda d,k="123": ["Open", d, f"--key={k}", "--max-unlock-time=3", "--dry-run", "--no-admin"]


def test_new_block_size(binary, device):
    create_test_device(device); assert_success(["New", device, "--target-level=3", "--key=123", "--target-time=0.1", "--block-size=4096"] + F, binary); assert_success(_O(device), binary)

def test_new_no_detect_entropy(binary, device):
    create_test_device(device); assert_success(["New", device, "--target-level=3", "--key=123", "--target-time=0.1", "--no-detect-entropy"] + F, binary); assert_success(_O(device), binary)

def test_new_encrypt_type(binary, device):
    for ct in ["twofish-xts-plain64", "serpent-xts-plain64"]:
        create_test_device(device); assert_success(["New", device, "--target-level=3", "--key=123", "--target-time=0.1", "--encrypt-type=" + ct] + F, binary); assert_success(_O(device), binary)

def test_new_target_mem(binary, device):
    create_test_device(device); assert_success(["New", device, "--target-level=3", "--key=123", "--target-time=0.1", "--target-mem=131072"] + F, binary); assert_success(_O(device), binary)

def test_new_target_level(binary, device):
    create_test_device(device); assert_success(["New", device, "--key=123", "--target-time=0.1", "--target-level=3"] + F, binary); assert_success(_O(device), binary)

def test_new_key_file(binary, device):
    kf = "/tmp/wt-kf-" + uuid.uuid4().hex[:8]
    with open(kf, "wb") as f: f.write(b"keyfile-data\n")
    create_test_device(device)
    rc, so, se = run_windham(["New", device, "--target-level=3", "--key-file=" + kf, "--target-time=0.1"] + F, binary)
    os.remove(kf)
    assert rc == 0, f"New key-file failed: {so+se[:200]}"

# SKIP: requires non-Landlock environment
# # def test_new_keystdin_manual(binary, device):
#     create_test_device(device)
#     rc, so, se = run_windham(["New", device, "--target-level=3", "--keystdin", "--target-time=0.1"] + F, binary, stdin_text="mykey\n")
#     assert rc == 0, f"New keystdin failed: {so+se[:200]}"

def test_open_readonly(binary, device):
    create_test_device(device); assert_success(["New", device, "--target-level=3", "--key=123", "--target-time=0.1"] + F, binary); assert_success(["Open", device, "--key=123", "--max-unlock-time=3", "--readonly", "--dry-run", "--no-admin"], binary)

def test_addkey_target_mem(binary, device):
    create_test_device(device); assert_success(["New", device, "--target-level=3", "--key=123", "--target-time=0.1"] + F, binary); assert_success(["AddKey", device, "--key=123", "--target-time=0.1", "--target-mem=65536", "--generate-random-key", "--no-admin"], binary); assert_success(_O(device), binary)

def test_addkey_target_level(binary, device):
    create_test_device(device); assert_success(["New", device, "--key=123", "--target-time=0.1"] + F, binary); assert_success(["AddKey", device, "--key=123", "--target-time=0.1", "--target-level=3", "--generate-random-key", "--no-admin"], binary); assert_success(_O(device), binary)

def test_delkey_no_fill_pattern(binary, device):
    create_test_device(device); assert_success(["New", device, "--target-level=3", "--key=123", "--target-time=0.1"] + F, binary); assert_success(["AddKey", device, "--key=123", "--target-time=0.1", "--rapid-add", "--generate-random-key", "--no-admin"], binary); assert_success(["DelKey", device, "--key=123", "--max-unlock-time=3", "--no-fill-pattern", "--yes", "--no-admin"], binary)

def test_show_master_key(binary, device):
    """Open --show-master-key prints the 32-byte master key as spaced hex."""
    create_test_device(device)
    assert_success(["New", device, "--target-level=3", "--key=123", "--target-time=0.1"] + F, binary)
    so, _ = assert_success(["Open", device, "--key=123", "--max-unlock-time=3",
                            "--show-master-key", "--no-admin"], binary)
    assert re.fullmatch(r"([0-9a-f]{2} ){31}[0-9a-f]{2}", so.strip()), f"bad master key: {so!r}"

def test_bench(binary, device):
    """Bench runs the Argon2id benchmark without a device (~7 s, 4 GiB peak)."""
    rc, so, se = run_windham(["Bench"], binary, timeout=120)
    assert rc == 0, f"bench rc={rc}: {se[:200]}"
    assert "Starting Argon2id benchmark" in so
    assert "Parallel efficiency" in so

def test_open_nonexistent(binary, device):
    rc, so, se = run_windham(["Open", "/tmp/windham_no_such_device_file", "--key=123",
                              "--max-unlock-time=3", "--no-admin"], binary)
    assert rc != 0, f"open on nonexistent path should fail: {so[:200]}"

def test_open_uuid_prefix_rejected(binary, device):
    """The ISOC baseline has no UUID resolution: UUID= prefixes are rejected."""
    create_test_device(device)
    assert_success(["New", device, "--target-level=3", "--key=123", "--target-time=0.1"] + F, binary)
    rc, so, se = run_windham(["Open", "UUID=12345678-1234-1234-1234-123456789abc",
                              "--key=123", "--max-unlock-time=3", "--dry-run", "--no-admin"], binary)
    assert rc != 0, f"UUID= prefix should be rejected on ISOC: {so[:200]}"

test_open_uuid_prefix_rejected.requires = "isoc"

def test_close_unmapped_graceful(binary, device):
    """Close of an unmapped name warns (print/ff driver has no remove) and exits 0."""
    rc, so, se = run_windham(["Close", "windham-nonexistent-entry", "--no-admin"], binary)
    assert rc == 0, f"close rc={rc}: {so+se[:200]}"
