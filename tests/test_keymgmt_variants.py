"""Key management variants: anonymous, anonymous-del."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import run_windham, assert_success, assert_error, create_test_device

_FLAGS = ["--yes", "--no-admin", "--allow-swap"]
_NEW  = lambda d: ["New", d, "--key=123", "--target-time=0.1"] + _FLAGS
_OPEN = lambda d, k="123": ["Open", d, f"--key={k}", "--max-unlock-time=1", "--dry-run", "--no-admin", "--allow-swap"]

def test_anonymous_key(binary, device):
    """Add an anonymous key, verify it survives."""
    create_test_device(device)
    assert_success(_NEW(device), binary)
    assert_success(["AddKey", device, "--key=123", "--target-time=0.1", "--rapid-add",
                    "--generate-random-key", "--anonymous-key", "--no-admin", "--allow-swap"], binary)
    assert_success(_OPEN(device), binary)

def test_del_key_make_anonymous(binary, device):
    """Delete key, make anonymous."""
    create_test_device(device)
    assert_success(_NEW(device), binary)
    assert_success(["AddKey", device, "--key=123", "--target-time=0.1", "--rapid-add",
                    "--generate-random-key", "--no-admin", "--allow-swap"], binary)
    assert_success(["DelKey", device, "--key=123", "--yes", "--max-unlock-time=1", "--no-admin", "--allow-swap"], binary)
    assert_error(_OPEN(device), binary)
