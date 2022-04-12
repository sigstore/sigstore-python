import pretend
import pytest

import sigstore


@pytest.mark.xfail
def test_verify():
    filename = pretend.stub()
    assert sigstore.verify(filename) == "Nothing here yet"
