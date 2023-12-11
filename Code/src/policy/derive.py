import json
from typing import Dict, Any, Union
from .validate import validate
from .evaluate import evaluate
from .derive.factors.stack import stack
from .derive.key import key as derive_key

class KeyDerivation:
    """
    KeyDerivation class is used to derive a key based on a given policy and factors.

    Attributes:
        policy (dict): The policy based on which the key is derived.
        factors (dict): The factors used to derive the key.

    Methods:
        validate_and_evaluate(): Validates the policy and evaluates if there are sufficient factors to derive the key.
        expand_factors(): Expands the factors based on the policy.
        derive_key(): Derives a key based on the given policy and factors.

    Example usage:
    policy_value = {'factors': [{'type': 'stack', 'id': 'your_id', 'params': 'your_params'}]}
    factors_value = {'your_id': 'your_factor'}
    key_derivation_obj = KeyDerivation(policy_value, factors_value)
    result = key_derivation_obj.derive_key()
    print(result)
    """

    def __init__(self, policy: Dict[str, Any], factors: Dict[str, Any]):
        """
        The constructor for KeyDerivation class.

        Parameters:
            policy (dict): The policy based on which the key is derived.
            factors (dict): The factors used to derive the key.
        """
        self.policy = policy
        self.factors = factors

    def validate_and_evaluate(self):
        """
        Validates the policy and evaluates if there are sufficient factors to derive the key.

        Raises:
            TypeError: If the policy contains duplicate ids.
            ValueError: If there are insufficient factors to derive the key.
        """
        ids = list(self.factors.keys())
        if not validate(self.policy):
            raise TypeError('policy contains duplicate ids')
        if not evaluate(self.policy, ids):
            raise ValueError('insufficient factors to derive key')

    def expand_factors(self):
        """
        Expands the factors based on the policy.

        Returns:
            dict: The expanded factors.
        """
        parsed_factors = {}
        ids = list(self.factors.keys())

        for factor in self.policy['factors']:
            if factor['type'] == 'stack':
                if evaluate(factor['params'], ids):
                    parsed_factors[factor['id']] = stack(self.expand_factors(factor['params'], self.factors))
            else:
                if factor['id'] in ids:
                    parsed_factors[factor['id']] = self.factors[factor['id']]

        return parsed_factors

    async def derive_key(self):
        """
        Derives a key based on the given policy and factors.

        Returns:
            The derived key.
        """
        self.validate_and_evaluate()
        expanded = self.expand_factors()
        return await derive_key(self.policy, expanded)
