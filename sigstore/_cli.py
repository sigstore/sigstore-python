from importlib import resources

import click

from sigstore import sign, verify


@click.group()
def main():
    pass


@main.command("sign")
@click.option("identity_token", "--identity-token", type=click.STRING)
@click.option(
    "ctfe_pem",
    "--ctfe",
    type=click.File("rb"),
    default=resources.open_binary("sigstore._store", "ctfe.pub"),
)
@click.argument("file_", metavar="FILE", type=click.File("r"), required=True)
def _sign(file_, identity_token, ctfe_pem):
    click.echo(
        sign(
            file_=file_,
            identity_token=identity_token,
            ctfe_pem=ctfe_pem,
            output=click.echo,
        )
    )


@main.command("verify")
@click.option("certificate_path", "--cert", type=click.File("r"), required=True)
@click.option("signature_path", "--signature", type=click.File("r"), required=True)
@click.option("cert_email", "--cert-email", type=str)
@click.argument("file_", metavar="FILE", type=click.File("r"), required=True)
def _verify(file_, certificate_path, signature_path, cert_email):
    click.echo(
        verify(
            file_=file_,
            certificate_path=certificate_path,
            signature_path=signature_path,
            cert_email=cert_email,
            output=click.echo,
        )
    )
