from zxcvbn import zxcvbn
from functools import partial

def password(password):
    if not isinstance(password, str):
        raise TypeError('password must be a string')
    if len(password) == 0:
        raise ValueError('password cannot be empty')

    strength = zxcvbn(password)

    async def generate_factor(params):
        return {
            'type': 'password',
            'data': password.encode('utf-8'),
            'params': partial(lambda **params: {}, **params),
            'output': partial(lambda **params: {'strength': strength}, **params)
        }

    return generate_factor

# Example usage:
password_value = 'your_password'
factor_generator = password(password_value)
result = factor_generator({})
print(result)
