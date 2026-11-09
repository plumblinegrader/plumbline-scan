#!/bin/bash
cat > /app/greet.py <<'PY'
def greet(name):
    message = "Hello, " + name + "! Nice to meet you."
    return message
PY
