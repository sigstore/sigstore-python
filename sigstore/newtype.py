import base64

class b64str:

    def __init__(self, b64_encoded_str):
        self.b64str = b64_encoded_str

    def convert_b64(self, non_b64str):
        sample_string = non_b64str.encode('ascii')
        base64bytes = base64.b64encode(sample_string)
        self.b64str = base64bytes.decode('ascii')

class pemcert:

    def __init__(self, pemcert_str):
        self.pemcert = pemcert_str

    
class KeyID:
    # should take whatever the return type of hashlib.sha256(public_bytes).digest()
    def __init__(self, bytes):
        # self.bytes = bytes
        self.keyID = bytes


# class archetype includes 
# 1) initialization -> previous type (str, bytes)
# 2) assigning of member variables to information that can be extracted
# 3) other conversions (b64 to ascii?) (what is key ID) (pemcert to a layered b64?)
# 4) 