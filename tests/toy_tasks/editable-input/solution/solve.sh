#!/bin/bash
grep -ciE '^[aeiou]' /app/data/words.txt > /app/answer.txt
