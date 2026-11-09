import sys
sys.path.insert(0, "/app")
from greet import greet
assert greet("Ada") == "Hello, Ada! Nice to meet you.", greet("Ada")
assert greet("Bob") == "Hello, Bob! Nice to meet you."
print("ok")
