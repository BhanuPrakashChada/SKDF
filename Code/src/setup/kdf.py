import hashlib
import pbkdf2
import bcrypt
import scrypt
from argon2 import PasswordHasher
from hkdf import hkdf

class KeyDerivationFunction:
    """
        KeyDerivationFunction class is used to derive a key based on the given input, salt, size, and options.

        Attributes:
            input (str or bytes): The input string or bytes to derive the key from.
            salt (str or bytes): The salt string or bytes to use in the key derivation.
            size (int): The size of the derived key.
            options (dict): The options to use in the key derivation.

        Methods:
            validate_inputs(): Validates and converts the input and salt to bytes if they are strings.
            derive_key(): Derives a key based on the given input, salt, size, and options.

        Example usage:
            input_value = 'your_input'
            salt_value = 'your_salt'
            size_value = 32
            options_value = {'type': 'pbkdf2', 'params': {'rounds': 1000, 'digest': 'sha256'}}
            kdf_obj = KeyDerivationFunction(input_value, salt_value, size_value, options_value)
            result = kdf_obj.derive_key()
            print(result)
    """
    def __init__(self, input, salt, size, options):
        """
        The constructor for KeyDerivationFunction class.

        Parameters:
            input (str or bytes): The input string or bytes to derive the key from.
            salt (str or bytes): The salt string or bytes to use in the key derivation.
            size (int): The size of the derived key.
            options (dict): The options to use in the key derivation.
        """
        self.input = input
        self.salt = salt
        self.size = size
        self.options = options
        self.validate_inputs()

    def validate_inputs(self):
        """
        Validates and converts the input and salt to bytes if they are strings.
        """
        if isinstance(self.input, str):
            self.input = self.input.encode()
        if isinstance(self.salt, str):
            self.salt = self.salt.encode()

    def derive_key(self):
        """
        Derives a key based on the given input, salt, size, and options.

        Returns:
            The derived key.

        Raises:
            ValueError: If the type of key derivation function is not one of pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id.
        """
        if self.options['type'] == 'pbkdf2':
            return pbkdf2.pbkdf2_bin(self.input, self.salt, self.options['params']['rounds'], self.size, hashlib.new(self.options['params']['digest']).digest())
        elif self.options['type'] == 'bcrypt':
            input_hash = hashlib.sha256(self.input).digest().decode('base64')
            salt_hash = hashlib.sha256(self.salt).digest().decode('base64').replace('+', '.')
            hashed = bcrypt.hashpw(input_hash, '$2a$' + str(self.options['params']['rounds']) + '$' + salt_hash)
            derived_key = pbkdf2.pbkdf2_bin(hashed, salt_hash, 1, self.size, hashlib.sha256().digest())
            return derived_key
        elif self.options['type'] == 'scrypt':
            return scrypt.hash(self.input, self.salt, self.options['params']['rounds'], self.options['params']['blocksize'], self.options['params']['parallelism'], self.size)
        elif self.options['type'] in ['argon2i', 'argon2d', 'argon2id']:
            ph = PasswordHasher(
                time_cost=self.options['params']['rounds'],
                memory_cost=self.options['params']['memory'],
                parallelism=self.options['params']['parallelism'],
                hash_len=self.size
            )
            return ph.hash(self.input)
        elif self.options['type'] == 'hkdf':
            return hkdf(self.options['params']['digest'], self.input, self.salt, '', self.size)
        else:
            raise ValueError('kdf should be one of pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id (default)')