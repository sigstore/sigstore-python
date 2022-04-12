import pretend
import pytest

import sigstore


@pytest.mark.xfail
def test_sign():
    file_ = pretend.stub()
    identity_token = pretend.stub()
    output = pretend.call_recorder(lambda s: None)

    assert sigstore.sign(file_, identity_token, output) == "Nothing here yet"
