import struct
import base64
from speakeasy import speakeasy
from functools import partial

def mod(n, m):
    return ((n % m) + m) % m

def hotp(code):
    if not isinstance(code, int):
        raise TypeError('code must be an integer')

    async def generate_factor(params):
        target = mod(params['offset'] + code, 10 ** params['digits'])
        buffer = struct.pack('>I', target)

        return {
            'type': 'hotp',
            'data': buffer,
            'params': partial(
                lambda key, **params: {
                    'hash': params['hash'],
                    'digits': params['digits'],
                    'pad': params['pad'],
                    'counter': params['counter'] + 1,
                    'offset': mod(target - int(speakeasy.hotp(
                        secret=base64.b64decode(params['pad']),
                        encoding='hex',
                        counter=params['counter'] + 1,
                        algorithm=params['hash'],
                        digits=params['digits']
                    )), 10 ** params['digits'])
                },
                key=params['key']
            ),
            'output': lambda: {}
        }

    return generate_factor

# Example usage:
code = 365287
factor_generator = hotp(code)
params = {'offset': 0, 'digits': 6, 'pad': base64.b64encode(b'your_secret_key'), 'counter': 0, 'hash': 'sha1', 'key': b'your_master_key'}
result = factor_generator(params)
print(result)
