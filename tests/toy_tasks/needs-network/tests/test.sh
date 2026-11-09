#!/bin/bash
mkdir -p /logs/verifier
# Fetch a test helper at run time (needs the network).
if python3 -c "import urllib.request; urllib.request.urlopen('https://pypi.org/simple/pip/', timeout=20)" \
   && python3 /tests/check.py; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
