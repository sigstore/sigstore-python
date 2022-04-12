from pathlib import Path

import click

from sigstore import sign, verify


BUNDLED_CTFE_KEY_PATH = Path(__file__).parent / "keys" / "ctfe.pub"


@click.group()
def main():
    pass


@main.command("sign")
@click.option("identity_token", "--identity-token", type=click.STRING)
@click.option(
    "ctfe_key_path",
    "--ctfe",
    type=click.Path(exists=True),
    default=BUNDLED_CTFE_KEY_PATH,
)
@click.argument("file_", metavar="FILE", type=click.File("r"), required=True)
def _sign(file_, identity_token, ctfe_key_path):
    click.echo(
        sign(
            file_=file_,
            identity_token=identity_token,
            ctfe_key_path=ctfe_key_path,
            output=click.echo,
        )
    )


@main.command("verify")
@click.option("certificate_path", "--cert", type=click.Path())
@click.option("signature_path", "--signature", type=click.Path())
@click.argument("file_", metavar="FILE", type=click.File("r"), required=True)
def _verify(file_, certificate_path, signature_path):
    click.echo(
        verify(
            filename=file_.name,
            certificate_path=certificate_path,
            signature_path=signature_path,
        )
    )
