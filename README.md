# Rudimentary Transport Relay Driver (RTRD)
P2P UDP tunnel driver for Linux, inspired by WireGuard.

**This project is still in development!!! Do NOT use it outside a VM!!!!!!!!**

## Requirements
- Linux kernel source (tested on 6.12.49)
- Build tools: `gcc`, `make`, `flex`, `bison`, `bc`, `elfutils`
- QEMU for testing (optional but HIGHLY RECOMMENDED)

## Quick Start

### Building

#### Kernel
```sh
cd /path/to/linux-src
make allnoconfig
# TODO: Configuration (see https://github.com/wasdhjklxyz/nix-dev/blob/main/kernel/configure.sh for now :/)
make olddefconfig
make
```

#### Module
```sh
git clone https://github.com/wasdhjklxyz/rtrd.git
cd rtrd
make KDIR=/path/to/linux-src
```

### Usage

#### Machine A (192.0.2.2)
```sh
insmod rtrd.ko
ip link add rtrd0 type rtrd
echo "192.0.2.3" > /sys/class/net/rtrd0/peer
ip addr add 10.0.0.2/24 dev rtrd0
ip link set rtrd0 up

ping 10.0.0.2  # After Machine B setup
```

#### Machine B (192.0.2.3)
```sh
insmod rtrd.ko
ip link add rtrd0 type rtrd
echo "192.0.2.2" > /sys/class/net/rtrd0/peer
ip addr add 10.0.0.3/24 dev rtrd0
ip link set rtrd0 up

ping 10.0.0.2  # After Machine A setup
```

## Configuration

### View Peer
```sh
cat /sys/class/net/rtrd0/peer
```

### Set Peer
```sh
echo "192.0.2.3" > /sys/class/net/rtrd0/peer
```

## How It Works
```txt
TX: App -> rtrd0 -> Encap UDP -> eth0 -> Peer
RX: Peer -> eth0 -> Decap UDP -> rtrd0 -> App
```

## Debug
```sh
dmesg -w | grep rtrd
```

## License
GPL v2
