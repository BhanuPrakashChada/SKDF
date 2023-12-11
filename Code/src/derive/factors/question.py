from zxcvbn import zxcvbn

class Question:
    """
    Question class is used to handle question related operations.

    Attributes:
        answer (str): The answer string.
        strength (dict): The strength of the answer as calculated by zxcvbn.

    Methods:
        generate_factor(params): Returns a dictionary containing the type, data, params, and output of the answer.
        generate_params(params): Returns the input params as is.
        get_output(): Returns a dictionary containing the strength of the answer.

    Example usage:
        answer_value = 'Your_answer'
        question_obj = Question(answer_value)
        result = question_obj.generate_factor({})
        print(result)
    """
    def __init__(self, answer):
        """
        The constructor for Question class.

        Parameters:
            answer (str): The answer string.

        Raises:
            TypeError: If the answer is not a string.
            ValueError: If the answer is empty.
        """
        if not isinstance(answer, str):
            raise TypeError('answer must be a string')
        if len(answer) == 0:
            raise ValueError('answer cannot be empty')
        self.answer = answer.lower().replace(r'[^0-9a-z ]', '').strip()
        self.strength = zxcvbn(self.answer)

    def generate_factor(self, params):
        """
        Returns a dictionary containing the type, data, params, and output of the answer.

        Parameters:
            params (dict): A dictionary of parameters.

        Returns:
            dict: A dictionary containing the type, data, params, and output of the answer.
        """
        return {
            'type': 'question',
            'data': self.answer.encode('utf-8'),
            'params': self.generate_params(params),
            'output': self.get_output()
        }

    @staticmethod
    def generate_params(params):
        """
        Returns the input params as is.

        Parameters:
            params (dict): A dictionary of parameters.

        Returns:
            dict: The input params as is.
        """
        return params

    def get_output(self):
        """
        Returns a dictionary containing the strength of the answer.

        Returns:
            dict: A dictionary containing the strength of the answer.
        """
        return {'strength': self.strength}