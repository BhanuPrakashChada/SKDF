from typing import Dict, List

from typing import Dict, List

class PolicyEvaluator:
    """
    Evaluates a policy based on given factors.

    Args:
        policy (Dict[str, any]): The policy to evaluate.
        factors (List[str]): The factors to consider for evaluation.

    Example usage:
        policy_value = {'threshold': 2, 'factors': [{'type': 'stack', 'id': 'your_id', 'params': 'your_params'}]}
        factors_value = ['your_id']
        policy_evaluator_obj = PolicyEvaluator(policy_value, factors_value)
        result = policy_evaluator_obj.evaluate()
        print(result)
    """

    def __init__(self, policy: Dict[str, any], factors: List[str]):
        self.policy = policy
        self.factors = factors

    def evaluate(self) -> bool:
        """
        Evaluates the policy based on the given factors.

        Returns:
            bool: True if the policy is satisfied, False otherwise.
        """
        threshold = self.policy['threshold']
        actual = 0
        for factor in self.policy['factors']:
            if factor['type'] == 'stack':
                if self.evaluate_factor(factor['params']):
                    actual += 1
            else:
                if factor['id'] in self.factors:
                    actual += 1
        return actual >= threshold

    def evaluate_factor(self, factor_params):
        """
        Evaluates a single factor based on the given parameters.

        Args:
            factor_params (any): The parameters for the factor evaluation.

        Returns:
            bool: True if the factor is satisfied, False otherwise.
        """
        return PolicyEvaluator(factor_params, self.factors).evaluate()
