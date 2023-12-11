import json
from ajv import AJV
from hkdf import hkdf
from buffer_xor import xor
from secrets_combine import combine
from secrets_recover import recover
from kdf import kdf
from SKDFDerivedKey import SKDFDerivedKey

class Key:
    """
    Key class is used to handle key generation based on a policy and factors.

    Attributes:
        policy (dict): The policy for key generation.
        factors (dict): The factors for key generation.
        ajv (AJV): An instance of the AJV class for JSON schema validation.

    Methods:
        validate_policy(policy_schema): Validates the policy against a JSON schema.
        generate_key(): Generates a key based on the policy and factors.
        get_material(factor): Gets the material for a factor.
        get_secret(shares): Combines shares to get a secret.
        get_new_policy(new_factors, key_result): Gets a new policy based on new factors and a key result.
        get_original_shares(shares): Recovers the original shares from the shares.

    Example usage:
        policy_value = {
            'threshold': 2,
            'size': 16,
            'factors': [
                {'id': 'password', 'type': 'password', 'salt': 'your_salt', 'kdf': 'your_kdf', 'pad': 'your_pad'},
                {'id': 'hotp', 'type': 'hotp', 'salt': 'your_salt', 'kdf': 'your_kdf', 'pad': 'your_pad'},
                {'id': 'totp', 'type': 'totp', 'salt': 'your_salt', 'kdf': 'your_kdf', 'pad': 'your_pad'}
            ]
        }

        factors_value = {
            'password': password_factor_function,
            'hotp': hotp_factor_function,
            'totp': totp_factor_function
        }

        key_obj = Key(policy_value, factors_value)
        result = key_obj.generate_key()
        print(result)
    """
    def __init__(self, policy, factors):
        """
        The constructor for Key class.

        Parameters:
            policy (dict): The policy for key generation.
            factors (dict): The factors for key generation.

        Raises:
            TypeError: If the policy is not a dictionary or if the factors are not a dictionary.
        """
        self.policy = policy
        self.factors = factors
        self.ajv = AJV()

    def validate_policy(self, policy_schema):
        """
        Validates the policy against a JSON schema.

        Parameters:
            policy_schema (str): The JSON schema to validate the policy against.

        Raises:
            TypeError: If the policy is not valid according to the JSON schema.
        """
        valid = self.ajv.validate(json.loads(policy_schema), self.policy)
        if not valid:
            raise TypeError('Invalid key policy', self.ajv.errors)

    async def generate_key(self):
        """
        Generates a key based on the policy and factors.

        Returns:
            SKDFDerivedKey: An instance of the SKDFDerivedKey class representing the derived key.

        Raises:
            ValueError: If there are insufficient factors provided to derive the key.
        """
        self.validate_policy(policy_schema)

        if len(self.factors) < self.policy['threshold']:
            raise ValueError('Insufficient factors provided to derive key')

        shares = []
        new_factors = []
        outputs = {}

        for factor in self.policy['factors']:
            share, output, new_factor = await self.get_material(factor)
            shares.append(share)
            if output is not None:
                outputs[factor['id']] = output
            new_factors.append(new_factor)

        if len([x for x in shares if x is not None]) < self.policy['threshold']:
            raise ValueError('Insufficient factors provided to derive key')

        secret = self.get_secret(shares)
        key_result = await self.get_key_result(secret, factor)
        new_policy = self.get_new_policy(new_factors, key_result)
        original_shares = self.get_original_shares(shares)

        return SKDFDerivedKey(new_policy, key_result, secret, original_shares, outputs)

    async def get_material(self, factor):
        """
        Gets the material for a factor.

        Parameters:
            factor (dict): A dictionary representing a factor.

        Returns:
            tuple: A tuple containing the share, output, and new factor.
        """
        if factor['id'] in self.factors and callable(self.factors[factor['id']]):
            material = await self.factors[factor['id']](factor['params'])
            share = material['data'] if material['type'] == 'persisted' else xor(factor['pad'].encode('base64'), await hkdf('sha512', material['data'], '', '', self.policy['size']))
            output = await material['output']() if 'output' in material and callable(material['output']) else None
            new_factor = material['params']
        else:
            share = None
            output = None
            new_factor = None
        return share, output, new_factor

    @staticmethod
    def get_secret(shares):
        """
        Combines shares to get a secret.

        Parameters:
            shares (list): A list of shares.

        Returns:
            str: The combined secret.
        """
        return combine([x for x in shares if x is not None], self.policy['threshold'], len(self.policy['factors']))

    async def get_new_policy(self, new_factors, key_result):
        """
        Gets a new policy based on new factors and a key result.

        Parameters:
            new_factors (list): A list of new factors.
            key_result (str): The key result.

        Returns:
            dict: The new policy.
        """
        new_policy = json.loads(json.dumps(self.policy))
        for index, factor in enumerate(new_factors):
            if factor is not None and callable(factor):
                new_policy['factors'][index]['params'] = await factor({'key': key_result})
        return new_policy

    @staticmethod
    def get_original_shares(shares):
        """
        Recovers the original shares from the shares.

        Parameters:
            shares (list): A list of shares.

        Returns:
            list: The original shares.
        """
        return recover([x for x in shares if x is not None], self.policy['threshold'], len(self.policy['factors']))