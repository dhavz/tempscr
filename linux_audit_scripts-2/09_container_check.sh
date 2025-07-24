#!/bin/bash
echo "[+] Docker/LXC Check"
grep -q docker /proc/1/cgroup && echo "Docker detected"
grep -qa container=lxc /proc/1/environ && echo "LXC detected"
