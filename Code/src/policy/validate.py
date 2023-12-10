from typing import Dict, List

def ids(policy: Dict[str, any]) -> List[str]:
    id_list = []
    for factor in policy['factors']:
        id_list.append(factor['id'])
        if factor['type'] == 'stack':
            id_list.extend(ids(factor['params']))
    return id_list

def validate(policy: Dict[str, any]) -> bool:
    id_list = ids(policy)
    return len(set(id_list)) == len(id_list)
