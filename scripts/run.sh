#!/bin/sh

echo "Starting run.sh"

# Add a hosts record, pointing API endpoint to local loopback
echo "127.0.0.1   example.com" >>/etc/hosts
echo "127.0.0.1   www.example.com" >>/etc/hosts

./proxy "$@"