"""Comprehensive parameter tests for New/Open/AddKey/DelKey."""
import os, sys, uuid
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import run_windham, assert_success, assert_error, create_test_device

F  = ["--yes", "--no-admin", "--allow-swap"]
_O = lambda d,k="123": ["Open", d, f"--key={k}", "--max-unlock-time=1", "--dry-run", "--no-admin", "--allow-swap"]


def test_new_block_size(binary, device):
    create_test_device(device); assert_success(["New", device, "--key=123", "--target-time=0.1", "--block-size=4096"] + F, binary); assert_success(_O(device), binary)

def test_new_no_detect_entropy(binary, device):
    create_test_device(device); assert_success(["New", device, "--key=123", "--target-time=0.1", "--no-detect-entropy"] + F, binary); assert_success(_O(device), binary)

def test_new_encrypt_type(binary, device):
    for ct in ["twofish-xts-plain64", "serpent-xts-plain64"]:
        create_test_device(device); assert_success(["New", device, "--key=123", "--target-time=0.1", "--encrypt-type=" + ct] + F, binary); assert_success(_O(device), binary)

def test_new_target_mem(binary, device):
    create_test_device(device); assert_success(["New", device, "--key=123", "--target-time=0.1", "--target-mem=131072"] + F, binary); assert_success(_O(device), binary)

def test_new_target_level(binary, device):
    create_test_device(device); assert_success(["New", device, "--key=123", "--target-time=0.1", "--target-level=2"] + F, binary); assert_success(_O(device), binary)

def test_new_key_file(binary, device):
    kf = "/tmp/wt-kf-" + uuid.uuid4().hex[:8]
    with open(kf, "wb") as f: f.write(b"keyfile-data\n")
    create_test_device(device)
    rc, so, se = run_windham(["New", device, "--key-file=" + kf, "--target-time=0.1"] + F, binary)
    os.remove(kf)
    assert rc == 0, f"New key-file failed: {so+se[:200]}"

# SKIP: requires non-Landlock environment
# # def test_new_keystdin_manual(binary, device):
#     create_test_device(device)
#     rc, so, se = run_windham(["New", device, "--keystdin", "--target-time=0.1"] + F, binary, stdin_text="mykey\n")
#     assert rc == 0, f"New keystdin failed: {so+se[:200]}"

def test_open_readonly(binary, device):
    create_test_device(device); assert_success(["New", device, "--key=123", "--target-time=0.1"] + F, binary); assert_success(["Open", device, "--key=123", "--max-unlock-time=1", "--readonly", "--dry-run", "--no-admin", "--allow-swap"], binary)

def test_addkey_target_mem(binary, device):
    create_test_device(device); assert_success(["New", device, "--key=123", "--target-time=0.1"] + F, binary); assert_success(["AddKey", device, "--key=123", "--target-time=0.1", "--target-mem=65536", "--generate-random-key", "--no-admin", "--allow-swap"], binary); assert_success(_O(device), binary)

def test_addkey_target_level(binary, device):
    create_test_device(device); assert_success(["New", device, "--key=123", "--target-time=0.1"] + F, binary); assert_success(["AddKey", device, "--key=123", "--target-time=0.1", "--target-level=3", "--generate-random-key", "--no-admin", "--allow-swap"], binary); assert_success(_O(device), binary)

def test_delkey_no_fill_pattern(binary, device):
    create_test_device(device); assert_success(["New", device, "--key=123", "--target-time=0.1"] + F, binary); assert_success(["AddKey", device, "--key=123", "--target-time=0.1", "--rapid-add", "--generate-random-key", "--no-admin", "--allow-swap"], binary); assert_success(["DelKey", device, "--key=123", "--max-unlock-time=1", "--no-fill-pattern", "--yes", "--no-admin", "--allow-swap"], binary)
