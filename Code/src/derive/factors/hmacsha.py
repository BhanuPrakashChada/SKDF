import os
import hmac
import hashlib

class HMACSHA1:
    """
        # Example usage:
        response = b'your_hmac_sha1_response'
        hmacsha1 = HMACSHA1(response)
        params = {'pad': 'your_hex_pad', 'key': b'your_master_key'}
        result = hmacsha1.generate_factor(params)
        print(result)
    """
    def __init__(self, response):
        if not isinstance(response, bytes):
            raise TypeError('response must be bytes')
        self.response = response
        self.secret = None

    @staticmethod
    def xor_bytes(b1, b2):
        return bytes(x ^ y for x, y in zip(b1, b2))

    def generate_factor(self, params):
        self.secret = self.xor_bytes(self.response[:20], bytes.fromhex(params['pad']))
        return {
            'type': 'hmacsha1',
            'data': self.secret,
            'params': self.generate_params(params['key']),
            'output': self.get_output
        }

    def generate_params(self, key):
        return {
            'challenge': os.urandom(64).hex(),
            'pad': self.xor_bytes(hmac.new(self.secret, os.urandom(64), hashlib.sha1).digest()[:20], self.secret).hex()
        }

    def get_output(self):
        return {'secret': self.secret}