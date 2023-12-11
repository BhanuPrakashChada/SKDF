from zxcvbn import zxcvbn

class Question:
    """
        # Example usage:
        answer_value = 'Your_answer'
        question_obj = Question(answer_value)
        result = question_obj.generate_factor({})
        print(result)
    """
    def __init__(self, answer):
        if not isinstance(answer, str):
            raise TypeError('answer must be a string')
        if len(answer) == 0:
            raise ValueError('answer cannot be empty')
        self.answer = answer.lower().replace(r'[^0-9a-z ]', '').strip()
        self.strength = zxcvbn(self.answer)

    def generate_factor(self, params):
        return {
            'type': 'question',
            'data': self.answer.encode('utf-8'),
            'params': self.generate_params(params),
            'output': self.get_output()
        }

    @staticmethod
    def generate_params(params):
        return params

    def get_output(self):
        return {'strength': self.strength}