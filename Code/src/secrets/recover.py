import secrets
from typing import List, Optional

def recover(shares: List[Optional[bytes]], k: int, n: int) -> List[bytes]:
    if not isinstance(shares, list):
        raise TypeError('shares must be a list')
    if not shares:
        raise ValueError('shares must not be empty')
    if not isinstance(n, int) or n <= 0:
        raise ValueError('n must be a positive integer')
    if not isinstance(k, int) or k <= 0:
        raise ValueError('k must be a positive integer')
    if k > n:
        raise ValueError('k must be less than or equal to n')
    if len(shares) < k:
        raise ValueError('not enough shares provided to retrieve secret')

    if k == 1:  # 1-of-n
        return [next(x for x in shares if x is not None)] * n
    elif k == n:  # n-of-n
        return shares
    else:  # k-of-n
        if len(shares) != n:
            raise ValueError('provide a shares list of size n; use None for unknown shares')

        bits = max(int((n + 1).bit_length()), 3)
        secrets.init(bits)

        formatted = []

        for index, share in enumerate(shares):
            if share is not None:
                value = f'{bits} {index + 1:0{bits}x}{share.hex()}'
                formatted.append(value)

        if len(formatted) < k:
            raise ValueError('not enough shares provided to retrieve secret')

        new_shares = []

        for i in range(n):
            new_share = secrets.newShare(i + 1, formatted)
            components = secrets.extractShareComponents(new_share)
            if len(components.data) % 2 == 1:
                components.data = '0' + components.data

            new_shares.append(bytes.fromhex(components.data))

        return new_shares
