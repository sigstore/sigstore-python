from importlib import resources


def test_store_reads_fulcio_root_cert():
    fulcio_crt = resources.read_text("sigstore._store", "fulcio.crt.pem")

    assert fulcio_crt.startswith("-----BEGIN CERTIFICATE-----")
    assert fulcio_crt.endswith("-----END CERTIFICATE-----")


def test_store_reads_ctfe_pub():
    ctfe_pub = resources.read_text("sigstore._store", "ctfe.pub")

    assert ctfe_pub.startswith("-----BEGIN PUBLIC KEY-----")
    assert ctfe_pub.endswith("-----END PUBLIC KEY-----")
