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
# Manual setup
insmod rtrd.ko
ip link add rtrd0 type rtrd
echo "203.0.113.2" > /sys/class/net/rtrd0/peer
ip addr add 10.0.0.1/24 dev rtrd0
ip link set rtrd0 up
ip route add default via 192.0.2.1
ip route add 172.16.0.0/24 via 10.0.0.2 dev rtrd0

# Or use test script
./scripts/test.sh client
```

#### Machine B (203.0.113.2)
```sh
# Manual setup
insmod rtrd.ko
ip link add rtrd0 type rtrd
echo "192.0.2.2" > /sys/class/net/rtrd0/peer
ip addr add 10.0.0.2/24 dev rtrd0
ip link set rtrd0 up
ip route add default via 203.0.113.1
ip addr add 172.16.0.1/24 dev lo
echo 1 > /proc/sys/net/ipv4/ip_forward

# Or use test script
./scripts/test.sh peer
```

### Test
```sh
# From Machine A
ping 172.16.0.1
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
