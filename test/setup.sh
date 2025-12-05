#!/bin/sh

# Yes I know this script sucks

MODULE="rtrd"
IFACE="rtrd0"

if [ "$1" != "client" ] && [ "$1" != "peer" ]; then
    echo "Usage: $0 {client|peer}"
    exit 1
fi

ROLE="$1"

ip link set $IFACE down 2>/dev/null || true
ip link del $IFACE 2>/dev/null || true
rmmod $MODULE 2>/dev/null || true

insmod /mnt/host/${MODULE}.ko
ip link add $IFACE type $MODULE

if [ "$ROLE" = "client" ]; then
  TUNL_IP="10.0.0.1"
  PEER_IP="203.0.113.2"
elif [ "$ROLE" = "peer" ]; then
  TUNL_IP="10.0.0.2"
  PEER_IP="192.0.2.2"
fi

echo "$PEER_IP" > "/sys/class/net/$IFACE/peer"
ip addr add ${TUNL_IP}/24 dev $IFACE
ip link set $IFACE up

if [ "$ROLE" = "client" ]; then
  ip route add default via 192.0.2.1
  ip route add 172.16.0.0/24 via 10.0.0.2 dev $IFACE
elif [ "$ROLE" = "peer" ]; then
  ip route add default via 203.0.113.1
  ip addr add 172.16.0.1/24 dev lo
  echo 1 > /proc/sys/net/ipv4/ip_forward
fi
