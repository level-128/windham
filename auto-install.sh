#!/bin/bash
if command -v apt &> /dev/null; then
    distribution="debian"
elif command -v dnf &> /dev/null; then
    distribution="fedora"
elif command -v pacman &> /dev/null; then
    distribution="arch"
elif command -v zypper &> /dev/null; then
    distribution="suse"
elif command -v apk &> /dev/null; then
    distribution="alpine"
else
    distribution="unknown"
fi

echo "Detect package manager type: $distribution"
echo "Starting package installation..."

case "$distribution" in
    debian)
        apt-get update
        apt-get install -y cmake make gcc libdevmapper-dev libkeyutils-dev linux-headers-$(uname -r) libgettextpo-dev libblkid-dev kpartx clevis
        ;;
    fedora)
        dnf update
        dnf install -y cmake make gcc device-mapper-devel keyutils-devel kernel-devel gettext-runtime gettext-tools libblkid-devel kpartx clevis
        ;;
    arch)
        pacman -Sy
        pacman -S --noconfirm cmake make gcc device-mapper keyutils linux-headers gettext kpartx util-linux clevis
        ;;
    suse)
        zypper ref
        zypper in -y cmake make gcc device-mapper-devel keyutils-devel kernel-devel gettext-runtime gettext-tools libblkid-devel kpartx clevis
        ;;
    alpine)
        apk update
        apk add cmake make gcc lvm2-dev keyutils-dev linux-headers gettext-dev util-linux libblkid-dev
        ;;
    *)
        echo "Unsupported distribution! $distribution"
        exit 1
        ;;
esac

echo "Installation completed. Now compiling windham..."
# Navigate to the directory of this script and compile windham
cmake -B build
cd build
make -j
sudo make install
cd ..
rm -rf build
