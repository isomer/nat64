#!/bin/sh
set -xe

DEV=test0

ip link del $DEV || true
ip link del veth0 || true

ip link add $DEV type veth

#xdp-loader load -m skb $DEV nat46.o
#ip link set dev $DEV xdp object nat46.o program xdp_4to6 verbose
ip link set dev $DEV xdpgeneric obj nat46.o sec xdp verbose


ip link set up dev $DEV
ip addr add 10.0.1.1/24 dev $DEV

ip link set up dev veth0
ip addr add 10.0.0.3/24 metric 10 dev veth0

ip neigh add 10.0.0.2 lladdr 02:00:00:00:00:46 dev veth0 ||
    ip neigh replace 10.0.0.2 lladdr 02:00:00:00:00:46 dev veth0

cat /sys/kernel/tracing/trace_pipe
