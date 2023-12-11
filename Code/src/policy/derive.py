import json
from typing import Dict, Any, Union
from .validate import validate
from .evaluate import evaluate
from .derive.factors.stack import stack
from .derive.key import key as derive_key

class KeyDerivation:
    """
        # Example usage:
        policy_value = {'factors': [{'type': 'stack', 'id': 'your_id', 'params': 'your_params'}]}
        factors_value = {'your_id': 'your_factor'}
        key_derivation_obj = KeyDerivation(policy_value, factors_value)
        result = key_derivation_obj.derive_key()
        print(result)
    """
    def __init__(self, policy: Dict[str, Any], factors: Dict[str, Any]):
        self.policy = policy
        self.factors = factors

    def validate_and_evaluate(self):
        ids = list(self.factors.keys())
        if not validate(self.policy):
            raise TypeError('policy contains duplicate ids')
        if not evaluate(self.policy, ids):
            raise ValueError('insufficient factors to derive key')

    def expand_factors(self):
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
        self.validate_and_evaluate()
        expanded = self.expand_factors()
        return await derive_key(self.policy, expanded)
