from typing import Dict, List

def evaluate(policy: Dict[str, any], factors: List[str]) -> bool:
    threshold = policy['threshold']
    actual = 0
    for factor in policy['factors']:
        if factor['type'] == 'stack':
            if evaluate(factor['params'], factors):
                actual += 1
        else:
            if factor['id'] in factors:
                actual += 1
    return actual >= threshold
