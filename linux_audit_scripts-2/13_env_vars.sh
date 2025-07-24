#!/bin/bash
echo "[+] Environment Variables with Potential Risk"
env | grep -iE 'LD_PRELOAD|LD_LIBRARY_PATH|PATH'
