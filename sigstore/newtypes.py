from typing import NewType

hexstr = NewType('hexstr', str)
b64str = NewType('b64str', str)
pemcert = NewType("pemcert", str)
keyID = NewType('keyID', bytes)