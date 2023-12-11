import secrets
from typing import List, Optional

from typing import List, Optional

class SecretCombiner:
    """
    A class that combines secret shares to retrieve the original secret.

    Example usage:
    shares_value = [b'your_share']
    k_value = 1
    n_value = 1
    secret_combiner_obj = SecretCombiner(shares_value, k_value, n_value)
    result = secret_combiner_obj.combine()
    print(result)
    """

    def __init__(self, shares: List[Optional[bytes]], k: int, n: int):
        """
        Initializes a SecretCombiner object.

        Args:
            shares (List[Optional[bytes]]): A list of secret shares.
            k (int): The minimum number of shares required to retrieve the secret.
            n (int): The total number of shares.

        Raises:
            TypeError: If shares is not a list.
            ValueError: If shares is empty, n is not a positive integer, k is not a positive integer,
                        k is greater than n, or there are not enough shares provided to retrieve the secret.
        """
        self.shares = shares
        self.k = k
        self.n = n
        self.validate_inputs()

    def validate_inputs(self):
        """
        Validates the inputs provided for the SecretCombiner object.

        Raises:
            TypeError: If shares is not a list.
            ValueError: If shares is empty, n is not a positive integer, k is not a positive integer,
                        k is greater than n, or there are not enough shares provided to retrieve the secret.
        """
        if not isinstance(self.shares, list):
            raise TypeError('shares must be a list')
        if not self.shares:
            raise ValueError('shares must not be empty')
        if not isinstance(self.n, int) or self.n <= 0:
            raise ValueError('n must be a positive integer')
        if not isinstance(self.k, int) or self.k <= 0:
            raise ValueError('k must be a positive integer')
        if self.k > self.n:
            raise ValueError('k must be less than or equal to n')
        if len(self.shares) < self.k:
            raise ValueError('not enough shares provided to retrieve secret')

    def combine(self) -> bytes:
        """
        Combines the secret shares to retrieve the original secret.

        Returns:
            bytes: The original secret.

        Raises:
            ValueError: If the shares list size is not equal to n for k-of-n scheme,
                        or if there are not enough shares provided to retrieve the secret.
        """
        if self.k == 1:  # 1-of-n
            return next(x for x in self.shares if x is not None)
        elif self.k == self.n:  # n-of-n
            secret = self.shares[0]
            for share in self.shares[1:]:
                if share is not None:
                    secret = bytes(x ^ y for x, y in zip(secret, share))
            return secret
        else:  # k-of-n
            if len(self.shares) != self.n:
                raise ValueError('provide a shares list of size n; use None for unknown shares')

            bits = max(int((self.n + 1).bit_length()), 3)
            secrets.init(bits)

            formatted = []

            for index, share in enumerate(self.shares):
                if share is not None:
                    value = f'{bits} {index + 1:0{bits}x}{share.hex()}'
                    formatted.append(value)

            if len(formatted) < self.k:
                raise ValueError('not enough shares provided to retrieve secret')

            return bytes.fromhex(secrets.combine(formatted))
