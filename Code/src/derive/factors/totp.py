import struct
import base64
import time
from functools import partial

class TOTP:
    """
    TOTP class is used to generate Time-Based One-Time Passwords (TOTP).

    Attributes:
        code (int): The code used to generate the TOTP.
        options (dict): The options for generating the TOTP.

    Methods:
        mod(n, m): Returns the modulus of n by m.
        generate_factor(params): Generates the TOTP based on the given parameters.
        generate_params(params): Generates the parameters for the next TOTP.
        get_output(): Returns an empty dictionary.

    Example usage:
        code_value = 528258
        options_value = {'time': 1650430943604}
        totp_obj = TOTP(code_value, options_value)
        params_value = {'offsets': 'your_offsets_base64', 'start': 0, 'digits': 6, 'step': 30, 'window': 3, 'pad': 'your_pad', 'key': b'your_master_key'}
        result = totp_obj.generate_factor(params_value)
        print(result)
    """
    def __init__(self, code, options=None):
        """
        The constructor for TOTP class.

        Parameters:
            code (int): The code used to generate the TOTP.
            options (dict, optional): The options for generating the TOTP.

        Raises:
            TypeError: If the code is not an integer or if the time option is not an integer.
            ValueError: If the time option is not positive.
        """
        if not isinstance(code, int):
            raise TypeError('code must be an integer')
        if options is None:
            options = {}
        if 'time' not in options:
            options['time'] = int(time.time() * 1000)
        if not isinstance(options['time'], int):
            raise TypeError('time must be an integer')
        if options['time'] <= 0:
            raise ValueError('time must be positive')
        self.code = code
        self.options = options

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
        Generates the TOTP based on the given parameters.

        Parameters:
            params (dict): A dictionary containing 'offsets', 'start', 'digits', 'step', 'window', 'pad', and 'key'.

        Returns:
            dict: A dictionary containing 'type', 'data', 'params', and 'output'.
        """
        offsets = base64.b64decode(params['offsets'])
        start_counter = int(params['start'] / (params['step'] * 1000))
        now_counter = int(self.options['time'] / (params['step'] * 1000))

        index = now_counter - start_counter

        if index >= params['window']:
            raise ValueError('TOTP window exceeded')

        offset = struct.unpack('>I', offsets[4 * index:4 * (index + 1)])[0]

        target = self.mod(offset + self.code, 10 ** params['digits'])
        buffer = struct.pack('>I', target)

        return {
            'type': 'totp',
            'data': buffer,
            'params': self.generate_params(params),
            'output': self.get_output
        }

    def generate_params(self, params):
        """
        Generates the parameters for the next TOTP.

        Parameters:
            params (dict): A dictionary containing 'offsets', 'start', 'digits', 'step', 'window', 'pad', and 'key'.

        Returns:
            function: A function that when called, returns a dictionary containing 'start', 'hash', 'digits', 'step', 'window', 'pad', and 'offsets'.
        """
        return partial(
            lambda key, **params: {
                'start': self.options['time'],
                'hash': params['hash'],
                'digits': params['digits'],
                'step': params['step'],
                'window': params['window'],
                'pad': params['pad'],
                'offsets': base64.b64encode(params['offsets']).decode('utf-8')
            },
            key=params['key']
        )

    @staticmethod
    def get_output():
        """
        Returns an empty dictionary.

        Returns:
            dict: An empty dictionary.
        """
        return {}