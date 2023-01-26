import base64
import typing

b64str = typing.NewType('b64str', str)
pemcert = typing.NewType("pemcert", str)