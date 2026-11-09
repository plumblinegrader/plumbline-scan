def test_answer():
    out = open('/app/answer.txt').read()
    assert out.strip() == '17'
