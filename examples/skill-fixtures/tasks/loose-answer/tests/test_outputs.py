def test_answer():
    out = open('/app/answer.txt').read()
    assert '17' in out
