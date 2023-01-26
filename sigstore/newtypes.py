from typing import NewType

Hexstr = NewType('hexstr', str)
B64str = NewType('b64str', str)
Pemcert = NewType("pemcert", str)
KeyID = NewType('keyID', bytes)