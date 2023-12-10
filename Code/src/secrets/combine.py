import secrets
from typing import List, Optional

def combine(shares: List[Optional[bytes]], k: int, n: int) -> bytes:
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
        return next(x for x in shares if x is not None)
    elif k == n:  # n-of-n
        secret = shares[0]
        for share in shares[1:]:
            if share is not None:
                secret = bytes(x ^ y for x, y in zip(secret, share))
        return secret
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

        return bytes.fromhex(secrets.combine(formatted))
