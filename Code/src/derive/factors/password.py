from zxcvbn import zxcvbn

class Password:
    """
        # Example usage:
        password_value = 'Your_password'
        password_obj = Password(password_value)
        result = password_obj.generate_factor({})
        print(result)
    """
    def __init__(self, password):
        if not isinstance(password, str):
            raise TypeError('password must be a string')
        if len(password) == 0:
            raise ValueError('password cannot be empty')
        self.password = password
        self.strength = zxcvbn(self.password)

    async def generate_factor(self, params):
        return {
            'type': 'password',
            'data': self.password.encode('utf-8'),
            'params': self.get_params(params),
            'output': self.get_output()
        }

    @staticmethod
    def get_params(params):
        return {}

    def get_output(self):
        return {'strength': self.strength}