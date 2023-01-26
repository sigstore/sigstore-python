from typing import NewType

b64str = NewType('b64str', str)
pemcert = NewType("pemcert", str)
keyID = NewType('keyID', bytes)