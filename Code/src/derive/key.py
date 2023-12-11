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
        # Example usage:
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
        self.policy = policy
        self.factors = factors
        self.ajv = AJV()

    def validate_policy(self, policy_schema):
        valid = self.ajv.validate(json.loads(policy_schema), self.policy)
        if not valid:
            raise TypeError('Invalid key policy', self.ajv.errors)

    async def generate_key(self):
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
        return combine([x for x in shares if x is not None], self.policy['threshold'], len(self.policy['factors']))

    async def get_new_policy(self, new_factors, key_result):
        new_policy = json.loads(json.dumps(self.policy))
        for index, factor in enumerate(new_factors):
            if factor is not None and callable(factor):
                new_policy['factors'][index]['params'] = await factor({'key': key_result})
        return new_policy

    @staticmethod
    def get_original_shares(shares):
        return recover([x for x in shares if x is not None], self.policy['threshold'], len(self.policy['factors']))