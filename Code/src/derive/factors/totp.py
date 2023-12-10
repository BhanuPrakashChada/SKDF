import struct
import base64
from speakeasy import speakeasy

def mod(n, m):
    return ((n % m) + m) % m

def totp(code, options=None):
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

    async def generate_factor(params):
        offsets = base64.b64decode(params['offsets'])
        start_counter = int(params['start'] / (params['step'] * 1000))
        now_counter = int(options['time'] / (params['step'] * 1000))

        index = now_counter - start_counter

        if index >= params['window']:
            raise ValueError('TOTP window exceeded')

        offset = struct.unpack('>I', offsets[4 * index:4 * (index + 1)])[0]

        target = mod(offset + code, 10 ** params['digits'])
        buffer = struct.pack('>I', target)

        return {
            'type': 'totp',
            'data': buffer,
            'params': partial(
                lambda key, **params: {
                    'start': options['time'],
                    'hash': params['hash'],
                    'digits': params['digits'],
                    'step': params['step'],
                    'window': params['window'],
                    'pad': params['pad'],
                    'offsets': base64.b64encode(new_offsets).decode('utf-8')
                },
                key=params['key']
            ),
            'output': lambda: {}
        }

    return generate_factor

# Example usage:
code_value = 528258
options_value = {'time': 1650430943604}
factor_generator = totp(code_value, options_value)
params_value = {'offsets': 'your_offsets_base64', 'start': 0, 'digits': 6, 'step': 30, 'window': 3, 'pad': 'your_pad', 'key': b'your_master_key'}
result = factor_generator(params_value)
print(result)
