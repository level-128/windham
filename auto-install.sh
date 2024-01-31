#!/bin/bash
# Function to detect the Linux distribution
detect_distribution () {
    if grep -q "Debian\|Ubuntu\|Linux Mint" /etc/os-release; then
        echo "debian"
    elif grep -q "Fedora\|CentOS\|Red Hat" /etc/os-release; then
        echo "fedora"
    elif grep -q "Arch\|Manjaro" /etc/os-release; then
        echo "arch"
    fi
}
distribution=$(detect_distribution)
echo "Detected distribution: $distribution"
echo "Starting package installation..."
# Redirect stdout to null
exec > /dev/null
if [ "$distribution" = "debian" ]; then
    apt-get update
    apt-get install -y cmake gcc libdevmapper-dev libkeyutils-dev libext2fs-dev linux-headers-$(uname -r) libgettextpo-dev libncurses-dev e2fsprogs dosfstools kpartx util-linux
elif [ "$distribution" = "fedora" ]; then
    dnf update
    dnf install -y cmake gcc device-mapper-devel keyutils-devel libext2fs-devel kernel-devel gettext-runtime gettext-tools ncurses-devel e2fsprogs dosfstools kpartx util-linux
elif [ "$distribution" = "arch" ]; then
    pacman -Sy
    pacman -S --noconfirm cmake gcc device-mapper keyutils e2fsprogs linux-headers gettext ncurses dosfstools kpartx util-linux
else
    exec > /dev/tty
    echo "Unsupported distribution!"
    exit 1
fi
# Redirect stdout back to the terminal
exec > /dev/tty

echo "Installation completed. Now compiling windham..."
# Navigate to the directory of this script and compile windham
cmake -B build
cd build
make
sudo make install
cd ..
rm -rf build