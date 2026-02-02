#!/bin/bash
set -e  # <--- THIS IS THE FIX

cargo b --release

# The script will only reach here if cargo succeeds
sudo setcap cap_net_admin=eip ./target/release/trust
./target/release/trust &
pid=$!

sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0

# Fix: lowercase 'kill', and catch Ctrl+C (INT) too
trap "kill $pid" INT TERM

wait $pid
