import click

from sigstore import sign, verify


@click.group()
def main():
    pass


@main.command("sign")
def _sign():
    click.echo(sign())


@main.command("verify")
def _verify():
    click.echo(verify())
