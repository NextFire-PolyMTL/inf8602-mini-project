#!/bin/bash -xe

# Pre-requisites
sudo apt update
sudo apt-get install -y make gcc libfuse-dev


# Underprivileged user
sudo useradd john --create-home --shell /bin/bash


# LSM BPF
## Disable AppArmor
sudo systemctl disable --now apparmor
## Enable BPF
sudo sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,bpf"/' /etc/default/grub
sudo update-grub
## Install build dependencies
sudo apt install -y clang pkg-config libbpf-dev python3-pip
sudo update-alternatives --set cc /usr/bin/clang
sudo pip3 install ninja meson
## Install bpftool
curl -L https://github.com/libbpf/bpftool/releases/download/v7.3.0/bpftool-v7.3.0-amd64.tar.gz | sudo tar xvz -C /usr/local/bin/
sudo chmod +x /usr/local/bin/bpftool
