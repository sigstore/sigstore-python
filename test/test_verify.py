import pretend
import pytest

import sigstore


@pytest.mark.xfail
def test_verify():
    filename = pretend.stub()
    certificate_path = pretend.stub()
    signature_path = pretend.stub()
    assert (
        sigstore.verify(filename, certificate_path, signature_path)
        == "Nothing here yet"
    )
