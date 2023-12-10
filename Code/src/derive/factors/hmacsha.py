import os
import hmac
import hashlib
from functools import partial

def xor_bytes(b1, b2):
    return bytes(x ^ y for x, y in zip(b1, b2))

def hmacsha1(response):
    if not isinstance(response, bytes):
        raise TypeError('response must be bytes')

    async def generate_factor(params):
        secret = xor_bytes(response[:20], bytes.fromhex(params['pad']))

        return {
            'type': 'hmacsha1',
            'data': secret,
            'params': partial(
                lambda key, **params: {
                    'challenge': os.urandom(64).hex(),
                    'pad': xor_bytes(hmac.new(secret, os.urandom(64), hashlib.sha1).digest()[:20], secret).hex()
                },
                key=params['key']
            ),
            'output': lambda: {'secret': secret}
        }

    return generate_factor

# Example usage:
response = b'your_hmac_sha1_response'
factor_generator = hmacsha1(response)
params = {'pad': 'your_hex_pad', 'key': b'your_master_key'}
result = factor_generator(params)
print(result)
