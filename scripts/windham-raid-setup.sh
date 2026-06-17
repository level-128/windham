#!/bin/bash
# windham-raid-setup — Set up redundant LINK_OPEN cascade for RAID.
#
# Usage:
#   sudo ./windham-raid-setup.sh /dev/sda /dev/sdb /dev/sdc
#   sudo ./windham-raid-setup.sh --pass=raidpass /dev/sd{a,b,c}
#
# Options:
#   --pass=<password>   Common password for all disks (default: prompt once)
#   --open-first=<disk>  Which disk to open to trigger cascade (default: first arg)
#   --dry-run            Print commands without executing

set -e

DRY_RUN=false
PASS=""
OPEN_FIRST=""

usage() {
    echo "Usage: $0 [--pass=<pw>] [--open-first=<disk>] [--dry-run] /dev/sda /dev/sdb ..."
    exit 1
}

# Parse args
DISKS=()
for arg in "$@"; do
    case "$arg" in
        --pass=*)       PASS="${arg#*=}" ;;
        --open-first=*) OPEN_FIRST="${arg#*=}" ;;
        --dry-run)      DRY_RUN=true ;;
        --help|-h)      usage ;;
        /dev/*)         DISKS+=("$arg") ;;
        *)              echo "Unknown argument: $arg"; usage ;;
    esac
done

N=${#DISKS[@]}
if (( N < 3 )); then
    echo "Need at least 3 disks for RAID 5+ cascade." >&2
    exit 1
fi
OPEN_FIRST="${OPEN_FIRST:-${DISKS[0]}}"

# Prompt for password if not given
if [[ -z "$PASS" ]]; then
    read -rsp "Common password for all disks: " PASS
    echo
    if [[ -z "$PASS" ]]; then
        echo "Empty password." >&2
        exit 1
    fi
fi

run() {
    if $DRY_RUN; then
        echo "  DRY-RUN: $*"
    else
        "$@"
    fi
}

echo "=== RAID cascade setup: $N disks ==="
echo "  Disks: ${DISKS[*]}"
echo "  Open-first: $OPEN_FIRST"
echo "  Fault tolerance: $(( (N-1)/2 )) disk(s)"

# Step 1: Create Windham on each disk
echo
echo "--- Step 1: Create Windham partitions ---"
for dev in "${DISKS[@]}"; do
    echo "  $dev …"
    run sudo windham New "$dev" --key="$PASS" --target-time=0.2 --yes --no-admin --allow-swap
done

# Step 2: Add redundant LINK_OPEN entries
echo
echo "--- Step 2: Add redundant LINK_OPEN entries ---"
prio=0
for src in "${DISKS[@]}"; do
    for dst in "${DISKS[@]}"; do
        [[ "$src" == "$dst" ]] && continue
        prio=$((prio + 1))
        echo "  $src → $dst (prio=$prio, SHORTCUT)"
        run sudo windham Aux "$src" --add-link="$dst" \
            --key="$PASS" --target-key="$PASS" \
            --link-prio=$prio --link-flag=SHORTCUT \
            --max-unlock-time=3 --max-unlock-memory=50000 \
            --yes --no-admin --allow-swap
    done
done

echo
echo "=== Setup complete ==="
echo
echo "To unlock the cascade:"
echo "  sudo windham Open $OPEN_FIRST --key=\"\$PASS\""
echo
echo "After all disks are mapped, assemble RAID:"
echo "  sudo mdadm --assemble /dev/md0 /dev/mapper/windham-*"
