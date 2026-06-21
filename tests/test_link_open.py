"""LINK_OPEN cascade test: create linked partitions and verify cascade opening."""
import os, sys, subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.utils import assert_success, create_test_device, TestFailure, run_windham

_FLAGS  = ["--yes", "--no-admin", "--allow-swap"]
_UNLOCK = ["--max-unlock-time=2", "--max-unlock-memory=500000"]
LOSETUP = "/usr/sbin/losetup"

def _new(device):
    return ["New", device, "--key=123", "--target-level=1", "--target-time=0.1"] + _FLAGS

def _add_link(src, dst):
    return ["Aux", src, "--aux-add-link", dst, "--key=123", "--aux-target-key=123"] + _UNLOCK + _FLAGS

def _open(device):
    return ["Open", device, "--key=123"] + _UNLOCK + _FLAGS

def _losetup_find_free():
    r = subprocess.run([LOSETUP, "-f"], capture_output=True, text=True)
    if r.returncode != 0:
        raise TestFailure(f"losetup -f failed: {r.stderr.strip()}")
    lp = r.stdout.strip()
    if not lp:
        raise TestFailure("losetup -f returned empty")
    return lp

def _losetup_attach(filepath, loopdev):
    r = subprocess.run([LOSETUP, loopdev, filepath], capture_output=True, text=True)
    if r.returncode != 0:
        raise TestFailure(f"losetup {loopdev} {filepath} failed: {r.stderr.strip()}")

def _losetup_detach(loopdev):
    subprocess.run([LOSETUP, "-d", loopdev], capture_output=True)

def _parse_uuid_hex(stdout):
    """Extract UUID from probe output, return without dashes."""
    for line in stdout.split('\n'):
        if 'UUID:' in line:
            parts = line.strip().split()
            for p in parts:
                p = p.strip().replace('-', '')
                if len(p) == 32:
                    try:
                        int(p, 16)
                        return p
                    except ValueError:
                        pass
    return None


def _strip_dashes(s):
    return s.replace('-', '')


def test_link_open_cascade(binary, device):
    N = 5
    all_disks = []
    all_loops = []

    try:
        for i in range(N + 1):
            path = f"/tmp/wh_lt_{i}"
            if os.path.exists(path):
                os.remove(path)
            create_test_device(path)
            all_disks.append(path)
            lp = _losetup_find_free()
            _losetup_attach(path, lp)
            all_loops.append(lp)

        for i, lp in enumerate(all_loops):
            rc, so, se = run_windham(_new(lp), binary, timeout=30)
            if rc != 0:
                raise TestFailure(f"New {lp} (disk {i}) failed: rc={rc}, stderr={se.strip()[:200]}")

        real_loops = all_loops[:N]
        temp_loop  = all_loops[N]
        temp_disk  = all_disks[N]

        link_map = [
            (0, 1), (0, 2),
            (1, 2), (1, 3),
            (2, 3), (2, 4),
            (3, 4), (3, N),
            (4, 0), (4, N),
        ]
        for si, (src, dst) in enumerate(link_map):
            src_loop = real_loops[src]
            dst_loop = all_loops[dst]
            rc, so, se = run_windham(_add_link(src_loop, dst_loop), binary, timeout=60)
            if rc != 0:
                raise TestFailure(
                    f"add-link #{si}: {src}->{dst} ({src_loop}->{dst_loop}) failed rc={rc}\n"
                    f"stdout: {so.strip()[-300:]}\nstderr: {se.strip()[-200:]}")

        _losetup_detach(temp_loop)
        os.remove(temp_disk)

        rc, so, se = run_windham(_open(real_loops[0]), binary, timeout=60)
        if rc != 0:
            raise TestFailure(
                f"Open {real_loops[0]} failed rc={rc}\n"
                f"stdout: {so.strip()[-500:]}\nstderr: {se.strip()[-200:]}")

        mapper_entries = os.listdir("/dev/mapper")
        windham_entries = [e for e in mapper_entries if e.startswith("windham-")]
        if len(windham_entries) < N:
            raise TestFailure(
                f"Expected >= {N} windham-* entries in /dev/mapper, got {len(windham_entries)}: {windham_entries}")

        uuids_expected = set()
        for lp in real_loops:
            r = subprocess.run(
                [binary, "Probe", "--dir=" + lp, "--no-admin"],
                capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                uid = _parse_uuid_hex(r.stdout)
                if uid:
                    uuids_expected.add(uid)
        if len(uuids_expected) < N:
            raise TestFailure(f"Could not probe all {N} devices, got {len(uuids_expected)} UUIDs")

        uuids_mapped = set()
        for entry in windham_entries:
            if entry.startswith("windham-"):
                uuids_mapped.add(_strip_dashes(entry[len("windham-"):]))

        missing = uuids_expected - uuids_mapped
        if missing:
            raise TestFailure(f"UUIDs not found in /dev/mapper: {missing}. Mapped: {uuids_mapped}")

        for entry in windham_entries:
            subprocess.run([binary, "Close", entry, "--no-admin"], capture_output=True)

    finally:
        for lp in real_loops:
            subprocess.run([LOSETUP, "-d", lp], capture_output=True)
        for d in all_disks[:N]:
            if os.path.exists(d):
                os.remove(d)
        if os.path.exists(temp_disk):
            try:
                os.remove(temp_disk)
            except OSError:
                pass
