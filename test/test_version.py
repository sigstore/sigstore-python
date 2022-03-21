import sigstore


def test_version():
    assert isinstance(sigstore.__version__, str)
