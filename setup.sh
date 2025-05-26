#!/bin/sh
set -xe

DEV=test0

ip link del $DEV || true
ip link del veth0 || true

ip link add $DEV type veth

# Disable checksum offload.  Possibly only needed for debugging checksums
ethtool -K veth0 tx-checksumming off rx-checksumming off

ip link set dev $DEV xdpgeneric obj nat64.o sec xdp verbose

ip link set up dev $DEV
ip addr add 10.0.1.1/24 dev $DEV

ip link set up dev veth0
ip addr add 10.0.0.3/24 metric 10 dev veth0

ip neigh add fe80::64 lladdr 02:00:00:00:00:64 dev veth0 ||
    ip neigh replace fe80::64 lladdr 02:00:00:00:00:64 dev veth0
ip neigh add 10.0.0.2 lladdr 02:00:00:00:00:64 dev veth0 ||
    ip neigh replace 10.0.0.2 lladdr 02:00:00:00:00:64 dev veth0

ip route add 64:ff9b:1::/96 via fe80::64 dev veth0

ip route add 192.168.4.4 via 10.0.0.2 dev veth0
ip neigh add proxy 192.168.4.4 dev wireless
ip addr add 64:ff9b:1::192.168.4.4 dev veth0

echo 1 | tee \
    /proc/sys/net/ipv4/conf/wireless/proxy_arp \
    /proc/sys/net/ipv4/conf/veth0/forwarding \
    /proc/sys/net/ipv4/conf/wireless/forwarding

cat /sys/kernel/tracing/trace_pipe
