import struct
import base64
from speakeasy import speakeasy

class HOTP:
    """
    HOTP class is used to generate HMAC-based One-Time Passwords (HOTP).

    Attributes:
        code (int): The code used to generate the HOTP.

    Methods:
        mod(n, m): Returns the modulus of n by m.
        generate_factor(params): Generates the HOTP based on the given parameters.
        generate_params(target, params): Generates the parameters for the next HOTP.
        get_output(): Returns an empty dictionary.

    Example usage:
        code = 365287
        hotp = HOTP(code)
        params = {'offset': 0, 'digits': 6, 'pad': base64.b64encode(b'your_secret_key'), 'counter': 0, 'hash': 'sha1', 'key': b'your_master_key'}
        result = hotp.generate_factor(params)
        print(result)
    """
    def __init__(self, code):
        """
        The constructor for HOTP class.

        Parameters:
            code (int): The code used to generate the HOTP.

        Raises:
            TypeError: If the code is not an integer.
        """
        if not isinstance(code, int):
            raise TypeError('code must be an integer')
        self.code = code

    @staticmethod
    def mod(n, m):
        """
        Returns the modulus of n by m.

        Parameters:
            n, m (int): The numbers to perform the modulus operation on.

        Returns:
            int: The modulus of n by m.
        """
        return ((n % m) + m) % m

    def generate_factor(self, params):
        """
        Generates the HOTP based on the given parameters.

        Parameters:
            params (dict): A dictionary containing 'offset', 'digits', 'pad', 'counter', 'hash', and 'key'.

        Returns:
            dict: A dictionary containing 'type', 'data', 'params', and 'output'.
        """
        target = self.mod(params['offset'] + self.code, 10 ** params['digits'])
        buffer = struct.pack('>I', target)

        return {
            'type': 'hotp',
            'data': buffer,
            'params': self.generate_params(target, params),
            'output': self.get_output
        }

    def generate_params(self, target, params):
        """
        Generates the parameters for the next HOTP.

        Parameters:
            target (int): The target number to generate the parameters for.
            params (dict): A dictionary containing 'offset', 'digits', 'pad', 'counter', 'hash', and 'key'.

        Returns:
            dict: A dictionary containing 'hash', 'digits', 'pad', 'counter', and 'offset'.
        """
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
        """
        Returns an empty dictionary.

        Returns:
            dict: An empty dictionary.
        """
        return {}