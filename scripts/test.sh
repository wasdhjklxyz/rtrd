#!/bin/sh

MODULE="rtrd"
IFACE="rtrd0"

if [ $# -ne 2 ]; then
  echo "Usage: $0 <tunnel-ip> <peer-ip>"
  exit 1
fi

TUNNEL_IP="$1"
PEER_IP="$2"

ip link set $IFACE down 2>/dev/null || true
ip link del $IFACE down 2>/dev/null || true
rmmod $MODULE 2>/dev/null || true

insmod /mnt/host/${MODULE}.ko
ip link add $IFACE type $MODULE
echo "$PEER_IP" > "/sys/class/net/$IFACE/peer"
ip addr add $TUNNEL_IP/24 dev $IFACE
ip link set $IFACE up
