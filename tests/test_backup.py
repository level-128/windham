"""Backup / Restore / Destroy tests."""

REQUIRES = "any"  # test block: isoc | gnu-linux | any
import os, sys, subprocess, hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import run_windham, assert_success, assert_error, create_test_device, TestFailure

_FLAGS = ["--yes", "--no-admin"]
_NEW  = lambda d: ["New", d, "--target-level=3", "--key=123", "--target-time=0.1"] + _FLAGS
_OPEN = lambda d: ["Open", d, "--key=123", "--max-unlock-time=3", "--dry-run", "--no-admin"]

def test_destroy(binary, device):
    """Destroy a device, verify it can no longer be opened."""
    create_test_device(device)
    assert_success(_NEW(device), binary)
    assert_success(["Destroy", device, "--yes", "--no-admin"], binary)
    assert_error(_OPEN(device), binary)

def test_backup(binary, device):
    """Backup writes a header backup file. Tolerates root-only failure on GNU/Linux."""
    bkf = device + ".backup"
    if os.path.exists(bkf):
        os.remove(bkf)
    create_test_device(device)
    assert_success(_NEW(device), binary)
    rc, so, se = run_windham(["Backup", device, "--to=" + bkf, "--yes", "--no-admin"], binary)
    if rc != 0:
        assert "root" in (so+se).lower() or "permission" in (so+se).lower(), f"backup unexpected: {so+se[:200]}"
    if os.path.exists(bkf):
        os.remove(bkf)

def test_backup_restore_roundtrip(binary, device):
    """Backup → Destroy → Restore → device opens again, aux entries survive."""
    bkf = device + ".roundtrip"
    if os.path.exists(bkf):
        os.remove(bkf)
    create_test_device(device)
    assert_success(_NEW(device), binary)
    assert_success(["Aux", device, "--aux-add=survivor", "--key=123",
                    "--max-unlock-time=3", "--no-admin"], binary)
    assert_success(["Backup", device, "--to=" + bkf, "--yes", "--no-admin"], binary)
    assert_success(["Destroy", device, "--yes", "--no-admin"], binary)
    assert_error(_OPEN(device), binary)
    assert_success(["Restore", device, "--to=" + bkf, "--yes", "--no-admin"], binary)
    assert_success(_OPEN(device), binary)
    so, _ = assert_success(["Aux", device, "--aux-probe", "--key=123",
                            "--max-unlock-time=3", "--no-admin"], binary)
    assert "survivor" in so, f"aux entry lost in roundtrip: {so[:300]}"
    os.remove(bkf)

def test_backup_fold_roundtrip(binary, device):
    """Fold backup (slot-0 + metadata) → Destroy → fold Restore → device opens."""
    fold_file = device + ".fold"
    if os.path.exists(fold_file):
        os.remove(fold_file)
    create_test_device(device)
    assert_success(_NEW(device), binary)
    assert_success(["Backup", device, "--fold", "--to=" + fold_file, "--key=123",
                    "--yes", "--no-admin"], binary)
    assert_success(["Destroy", device, "--yes", "--no-admin"], binary)
    assert_error(_OPEN(device), binary)
    assert_success(["Restore", device, "--fold", "--to=" + fold_file, "--key=123",
                    "--yes", "--no-admin"], binary)
    assert_success(_OPEN(device), binary)
    os.remove(fold_file)

def test_backup_restore_lossless(binary, device):
    """Backup → Destroy → Restore reproduces the device file byte-for-byte."""
    bkf = device + ".lossless"
    if os.path.exists(bkf):
        os.remove(bkf)

    def sha256(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    create_test_device(device)
    assert_success(_NEW(device), binary)
    assert_success(["Aux", device, "--aux-add=payload", "--key=123",
                    "--max-unlock-time=3", "--no-admin"], binary)
    before = sha256(device)

    assert_success(["Backup", device, "--to=" + bkf, "--yes", "--no-admin"], binary)
    assert_success(["Destroy", device, "--yes", "--no-admin"], binary)
    assert sha256(device) != before, "Destroy did not alter the device file"
    assert_success(["Restore", device, "--to=" + bkf, "--yes", "--no-admin"], binary)

    after = sha256(device)
    if after != before:
        raise TestFailure(f"Restore is not byte-identical: {before} -> {after}")
    os.remove(bkf)

def test_backup_qrcode(binary, device):
    """QR backup prints a terminal QR and writes a 1-bit BMP when given a path."""
    create_test_device(device)
    assert_success(_NEW(device), binary)
    so, _ = assert_success(["Backup", device, "--qrcode", "--key=123",
                            "--yes", "--no-admin"], binary)
    assert "█" in so, f"no terminal QR block in output: {so[:200]}"
    bmp = device + ".qr.bmp"
    if os.path.exists(bmp):
        os.remove(bmp)
    assert_success(["Backup", device, "--qrcode=" + bmp, "--key=123",
                    "--yes", "--no-admin"], binary)
    with open(bmp, "rb") as f:
        magic = f.read(2)
    assert magic == b"BM", f"not a BMP file: {magic!r}"
    os.remove(bmp)

def test_fold_backup_eof_stdin(binary, device):
    """Fold backup without --key and closed stdin must fail cleanly, not spin on EOF.

    Regression: the interactive password prompt treated EOF as an invalid
    input byte and rang the terminal bell in a tight loop forever."""
    fold_file = device + ".eof-fold"
    if os.path.exists(fold_file):
        os.remove(fold_file)
    create_test_device(device)
    assert_success(_NEW(device), binary)
    try:
        r = subprocess.run(
            [binary, "Backup", device, "--fold", "--to=" + fold_file,
             "--yes", "--no-admin"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise TestFailure("fold backup hung on closed stdin (EOF spin)")
    if r.returncode == 0:
        raise TestFailure("fold backup without a key should not succeed")
    if os.path.exists(fold_file):
        os.remove(fold_file)
