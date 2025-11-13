#!/bin/sh

MODULE="rtrd"
IFACE="rtrd0"

ip link set $IFACE down 2>/dev/null || true
rmmod $MODULE 2>/dev/null || true

insmod /mnt/host/${MODULE}.ko
ip link set $IFACE up
ip addr add 10.0.0.1/24 dev $IFACE
