from typing import Dict, List

class PolicyValidator:
    """
    A class that validates a policy.

    Example usage:
    policy_value = {'factors': [{'type': 'stack', 'id': 'your_id', 'params': 'your_params'}]}
    policy_validator_obj = PolicyValidator(policy_value)
    result = policy_validator_obj.validate()
    print(result)
    """

    def __init__(self, policy: Dict[str, any]):
        self.policy = policy

    def get_ids(self) -> List[str]:
        """
        Get a list of all the IDs in the policy.

        Returns:
            A list of IDs.
        """
        id_list = []
        for factor in self.policy['factors']:
            id_list.append(factor['id'])
            if factor['type'] == 'stack':
                id_list.extend(PolicyValidator(factor['params']).get_ids())
        return id_list

    def validate(self) -> bool:
        """
        Validate the policy.

        Returns:
            True if the policy is valid, False otherwise.
        """
        id_list = self.get_ids()
        return len(set(id_list)) == len(id_list)