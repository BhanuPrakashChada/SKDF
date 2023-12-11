import struct
import base64
from speakeasy import speakeasy

class HOTP:
    """
        # Example usage:
        code = 365287
        hotp = HOTP(code)
        params = {'offset': 0, 'digits': 6, 'pad': base64.b64encode(b'your_secret_key'), 'counter': 0, 'hash': 'sha1', 'key': b'your_master_key'}
        result = hotp.generate_factor(params)
        print(result)
    """
    def __init__(self, code):
        if not isinstance(code, int):
            raise TypeError('code must be an integer')
        self.code = code

    @staticmethod
    def mod(n, m):
        return ((n % m) + m) % m

    def generate_factor(self, params):
        target = self.mod(params['offset'] + self.code, 10 ** params['digits'])
        buffer = struct.pack('>I', target)

        return {
            'type': 'hotp',
            'data': buffer,
            'params': self.generate_params(target, params),
            'output': self.get_output
        }

    def generate_params(self, target, params):
        return {
            'hash': params['hash'],
            'digits': params['digits'],
            'pad': params['pad'],
            'counter': params['counter'] + 1,
            'offset': self.mod(target - int(speakeasy.hotp(
                secret=base64.b64decode(params['pad']),
                encoding='hex',
                counter=params['counter'] + 1,
                algorithm=params['hash'],
                digits=params['digits']
            )), 10 ** params['digits'])
        }

    def get_output(self):
        return {}