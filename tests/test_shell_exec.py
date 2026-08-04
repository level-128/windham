"""SHELL aux command execution test — verify commands execute on Open."""
import os, sys, subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import assert_success, create_test_device, TestFailure, run_windham

_FLAGS  = ["--yes", "--no-admin"]
_UNLOCK = ["--max-unlock-time=3", "--max-unlock-memory=500000"]
LOSETUP = "/usr/sbin/losetup"

def _new(device):
    return ["New", device, "--key=123", "--target-level=3", "--target-time=0.1"] + _FLAGS

def _open(device, **kw):
    cmd = ["Open", device, "--key=123"] + _UNLOCK + _FLAGS
    if kw.get("dry_run"):
        cmd.append("--dry-run")
    return cmd

def _losetup_find_free():
    return subprocess.run([LOSETUP, "-f"], capture_output=True, text=True).stdout.strip()

def _losetup_attach(filepath, loopdev):
    subprocess.run([LOSETUP, loopdev, filepath], check=True, capture_output=True)

def _losetup_detach(loopdev):
    subprocess.run([LOSETUP, "-d", loopdev], capture_output=True)


def test_shell_exec_basic(binary, device):
    """Create a device, add a SHELL command that appends to a file, open and verify."""
    outfile = "/tmp/windham_shell_test_output"
    if os.path.exists(outfile):
        os.remove(outfile)

    create_test_device(device)
    assert_success(_new(device), binary)

    # Add a SHELL command that writes to a file
    assert_success(
        ["Aux", device, "--aux-add-command=echo hello >> " + outfile,
         "--aux-flag=",
         "--key=123"] + _UNLOCK + _FLAGS, binary)

    # Probe to verify the aux entry exists
    rc, so, se = run_windham(
        ["Aux", device, "--aux-probe", "--key=123"] + _UNLOCK + _FLAGS, binary)
    assert "SHELL" in so, f"probe output missing SHELL: {so[:200]}"

    # Open — should execute the command
    rc, so, se = run_windham(_open(device), binary)
    if rc != 0:
        raise TestFailure(f"Open failed: {so[-300:]}\n{se[-200:]}")

    # Verify the file was written
    if not os.path.exists(outfile):
        raise TestFailure(f"Output file {outfile} was not created by SHELL command")
    with open(outfile) as f:
        content = f.read()
    if "hello" not in content:
        raise TestFailure(f"Output file content mismatch: {content}")
    os.remove(outfile)


def test_shell_command_dry_run(binary, device):
    """Verify SHELL commands are NOT executed during dry-run."""
    outfile = "/tmp/windham_shell_test_dry"
    if os.path.exists(outfile):
        os.remove(outfile)

    create_test_device(device)
    assert_success(_new(device), binary)
    assert_success(
        ["Aux", device, "--aux-add-command=echo should_not_run >> " + outfile,
         "--key=123"] + _UNLOCK + _FLAGS, binary)

    # Dry-run should NOT execute the command
    rc, so, se = run_windham(_open(device, dry_run=True), binary)
    if rc != 0:
        raise TestFailure(f"Dry-run Open failed: {so[-200:]}")

    if os.path.exists(outfile):
        os.remove(outfile)
        raise TestFailure("SHELL command should NOT execute during --dry-run")


def test_shell_flag_blckopen(binary, device):
    """BLCKOPEN flag: succeeding command stops remaining aux entries."""
    out1 = "/tmp/windham_shell_flag1"
    out2 = "/tmp/windham_shell_flag2"
    for f in (out1, out2):
        if os.path.exists(f):
            os.remove(f)

    create_test_device(device)
    assert_success(_new(device), binary)

    # Add a SHELL command that always succeeds, with BLCKOPEN flag
    assert_success(
        ["Aux", device, "--aux-add-command=echo first >> " + out1,
         "--aux-flag=BLCKOPEN", "--key=123"] + _UNLOCK + _FLAGS, binary)

    # Add a second SHELL command (no flag)
    assert_success(
        ["Aux", device, "--aux-add-command=echo second >> " + out2,
         "--key=123"] + _UNLOCK + _FLAGS, binary)

    rc, so, se = run_windham(_open(device), binary)
    if rc != 0:
        raise TestFailure(f"Open failed: {so[-300:]}")

    # First command should have executed
    if not os.path.exists(out1):
        raise TestFailure("First SHELL command did not execute")
    with open(out1) as f:
        c1 = f.read()

    # Second command should NOT have executed (stopped by BLCKOPEN on success)
    if os.path.exists(out2):
        with open(out2) as f:
            c2 = f.read()
        raise TestFailure(
            f"Second SHELL command should NOT have executed (BLCKOPEN should stop after success).\n"
            f"first: {c1.strip()}, second: {c2.strip()}")

    assert "first" in c1, f"first command output missing: {c1}"
    for f in (out1, out2):
        if os.path.exists(f):
            os.remove(f)


def test_shell_at_replacement(binary, device):
    """'@' in SHELL command replaced with comma-separated opened mapper names."""
    outfile = "/tmp/windham_shell_at_test"
    if os.path.exists(outfile):
        os.remove(outfile)

    N = 2
    disks = []
    loops = []

    try:
        for i in range(N):
            path = f"/tmp/wh_shell_at_{i}"
            if os.path.exists(path):
                os.remove(path)
            create_test_device(path)
            disks.append(path)
            lp = _losetup_find_free()
            _losetup_attach(path, lp)
            loops.append(lp)

        for lp in loops:
            assert_success(_new(lp), binary, timeout=30)

        # Link disk 0 → disk 1
        _add_link = ["Aux", loops[0], "--aux-add-link", loops[1],
                     "--key=123", "--aux-target-key=123"] + _UNLOCK + _FLAGS
        assert_success(_add_link, binary, timeout=60)

        # Add SHELL command on disk 0 that writes "@" to a file
        # "@" will be replaced with space-separated /dev/mapper/<name> list
        assert_success(
            ["Aux", loops[0], "--aux-add-command=echo @ > " + outfile,
             "--key=123"] + _UNLOCK + _FLAGS, binary, timeout=60)

        # Open disk 0 — cascade opens disk 1, then SHELL executes
        rc, so, se = run_windham(_open(loops[0]), binary, timeout=60)
        if rc != 0:
            raise TestFailure(f"Open failed: {so[-300:]}\n{se[-200:]}")

        # Verify output contains /dev/mapper/windham- names separated by space
        if not os.path.exists(outfile):
            raise TestFailure(f"Output file {outfile} was not created")
        with open(outfile) as f:
            content = f.read().strip()

        # Should contain space-separated /dev/mapper/windham- names
        names = content.split()
        if len(names) != N:
            raise TestFailure(
                f"Expected {N} /dev/mapper/ names separated by space, got: {content}")
        for n in names:
            if not n.startswith("/dev/mapper/windham-"):
                raise TestFailure(f"Name does not start with '/dev/mapper/windham-': {n}")

        # Close all active Windham devices
        for n in names:
            subprocess.run([binary, "Close", n, "--no-admin"], capture_output=True)

    finally:
        for lp in loops:
            _losetup_detach(lp)
        for d in disks:
            if os.path.exists(d):
                os.remove(d)
        if os.path.exists(outfile):
            os.remove(outfile)

