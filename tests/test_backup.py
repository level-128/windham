"""Backup / Restore / Destroy tests."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import run_windham, assert_success, assert_error, create_test_device

_FLAGS = ["--yes", "--no-admin"]
_NEW  = lambda d: ["New", d, "--target-level=3", "--key=123", "--target-time=0.1"] + _FLAGS
_OPEN = lambda d: ["Open", d, "--key=123", "--max-unlock-time=1", "--dry-run", "--no-admin"]

def test_destroy(binary, device):
    """Destroy a device, verify it can no longer be opened."""
    create_test_device(device)
    assert_success(_NEW(device), binary)
    assert_success(["Destroy", device, "--yes", "--no-admin"], binary)
    assert_error(_OPEN(device), binary)

def test_backup(binary, device):
    """Backup requires root — skip gracefully if not root."""
    # Clean up leftover backup from previous runs
    if os.path.exists("windham_backup"):
        os.remove("windham_backup")
    create_test_device(device)
    assert_success(_NEW(device), binary)
    bkf = device + ".backup"
    rc, so, se = run_windham(["Backup", device, bkf, "--yes", "--no-admin"], binary)
    if rc != 0:
        assert "root" in (so+se).lower() or "permission" in (so+se).lower(), f"backup unexpected: {so+se[:200]}"
    if os.path.exists(bkf): os.remove(bkf)
