import sigstore


def test_sign():
    assert sigstore.sign() == "Nothing here yet"


def test_verify():
    assert sigstore.verify() == "Nothing here yet"
