import json
from typing import Dict, Any, Union
from .validate import validate
from .evaluate import evaluate
from .derive.factors.stack import stack
from .derive.key import key as derive_key

def expand(policy: Dict[str, Any], factors: Dict[str, Any]) -> Dict[str, Any]:
    parsed_factors = {}
    ids = list(factors.keys())

    for factor in policy['factors']:
        if factor['type'] == 'stack':
            if evaluate(factor['params'], ids):
                parsed_factors[factor['id']] = stack(expand(factor['params'], factors))
        else:
            if factor['id'] in ids:
                parsed_factors[factor['id']] = factors[factor['id']]

    return parsed_factors

async def derive(policy: Dict[str, Any], factors: Dict[str, Any]) -> Dict[str, Union[str, Dict[str, Any]]]:
    ids = list(factors.keys())
    if not validate(policy):
        raise TypeError('policy contains duplicate ids')
    if not evaluate(policy, ids):
        raise ValueError('insufficient factors to derive key')

    expanded = expand(policy, factors)

    return await derive_key(policy, expanded)