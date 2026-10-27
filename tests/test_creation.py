"""Basic device creation, open, and close tests."""

REQUIRES = "any"  # test block: isoc | gnu-linux | any
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import run_windham, assert_success, assert_error, create_test_device

def _new(device): return ["New", device, "--target-level=3", "--key=123", "--target-time=0.1", "--yes", "--no-admin"]
def _open(device, key="123"): return ["Open", device, f"--key={key}", "--max-unlock-time=3", "--dry-run", "--no-admin"]

def test_new(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)

def test_open_dry_run(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(_open(device), binary)

def test_wrong_password(binary, device):
    create_test_device(device)
    assert_success(_new(device), binary)
    assert_error(_open(device, key="wrong"), binary)

def test_open_key_file(binary, device):
    """Create with --key-file and unlock with the same key file."""
    kf = device + ".keyfile"
    with open(kf, "wb") as f:
        f.write(b"keyfile-data\n")
    try:
        create_test_device(device)
        assert_success(["New", device, "--key-file=" + kf,
                        "--target-level=3", "--target-time=0.1", "--yes", "--no-admin"], binary)
        assert_success(["Open", device, "--key-file=" + kf,
                        "--max-unlock-time=3", "--dry-run", "--no-admin"], binary)
        # a different key file must not unlock
        with open(kf, "wb") as f:
            f.write(b"other-data\n")
        assert_error(["Open", device, "--key-file=" + kf,
                      "--max-unlock-time=3", "--dry-run", "--no-admin"], binary)
    finally:
        os.remove(kf)
