from zxcvbn import zxcvbn

class Password:
    """
    Password class is used to handle password related operations.

    Attributes:
        password (str): The password string.
        strength (dict): The strength of the password as calculated by zxcvbn.

    Methods:
        generate_factor(params): Returns a dictionary containing the type, data, params, and output of the password.
        get_params(params): Returns an empty dictionary.
        get_output(): Returns a dictionary containing the strength of the password.

    Example usage:
        password_value = 'Your_password'
        password_obj = Password(password_value)
        result = await password_obj.generate_factor({})
        print(result)
    """
    def __init__(self, password):
        """
        The constructor for Password class.

        Parameters:
            password (str): The password string.

        Raises:
            TypeError: If the password is not a string.
            ValueError: If the password is empty.
        """
        if not isinstance(password, str):
            raise TypeError('password must be a string')
        if len(password) == 0:
            raise ValueError('password cannot be empty')
        self.password = password
        self.strength = zxcvbn(self.password)

    async def generate_factor(self, params):
        """
        Returns a dictionary containing the type, data, params, and output of the password.

        Parameters:
            params (dict): A dictionary of parameters.

        Returns:
            dict: A dictionary containing the type, data, params, and output of the password.
        """
        return {
            'type': 'password',
            'data': self.password.encode('utf-8'),
            'params': self.get_params(params),
            'output': self.get_output()
        }

    @staticmethod
    def get_params(params):
        """
        Returns an empty dictionary.

        Parameters:
            params (dict): A dictionary of parameters.

        Returns:
            dict: An empty dictionary.
        """
        return {}

    def get_output(self):
        """
        Returns a dictionary containing the strength of the password.

        Returns:
            dict: A dictionary containing the strength of the password.
        """
        return {'strength': self.strength}