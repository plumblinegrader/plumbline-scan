#!/bin/bash
mkdir -p /logs/verifier
if [ -f /app/greet.py ]; then echo 1 > /logs/verifier/reward.txt; else echo 0 > /logs/verifier/reward.txt; fi
