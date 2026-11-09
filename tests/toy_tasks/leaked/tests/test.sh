#!/bin/bash
mkdir -p /logs/verifier
cd /app
if python3 -c "from shapes import Rectangle; assert Rectangle(3, 4).area() == 12"; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
