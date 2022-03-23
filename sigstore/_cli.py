import click

from sigstore import sign, verify


@click.group()
def main():
    pass


@main.command("sign")
@click.option("identity_token", "--identity-token", type=click.STRING)
@click.argument("file_", metavar="FILE", type=click.File("r"), required=True)
def _sign(file_, identity_token):
    click.echo(sign(file_=file_, identity_token=identity_token, output=click.echo))


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
