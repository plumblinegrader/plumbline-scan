words = open("/app/data/words.txt").read().split()
expected = sum(w[0].lower() in "aeiou" for w in words)
got = int(open("/app/answer.txt").read().strip())
assert got == expected, (got, expected)
