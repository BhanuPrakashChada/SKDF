from zxcvbn import zxcvbn
from functools import partial

def question(answer):
    if not isinstance(answer, str):
        raise TypeError('answer must be a string')
    if len(answer) == 0:
        raise ValueError('answer cannot be empty')

    answer = answer.lower().replace(r'[^0-9a-z ]', '').strip()
    strength = zxcvbn(answer)

    async def generate_factor(params):
        return {
            'type': 'question',
            'data': answer.encode('utf-8'),
            'params': partial(lambda **params: params, **params),
            'output': partial(lambda **params: {'strength': strength}, **params)
        }

    return generate_factor

# Example usage:
answer_value = 'Your_answer'
factor_generator = question(answer_value)
result = factor_generator({})
print(result)
