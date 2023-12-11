import secrets
from typing import List, Optional

class SecretRecoverer:
    """
    # Example usage:
    shares_value = [b'your_share']
    k_value = 1
    n_value = 1
    secret_recoverer_obj = SecretRecoverer(shares_value, k_value, n_value)
    result = secret_recoverer_obj.recover()
    print(result)
    """

    def __init__(self, shares: List[Optional[bytes]], k: int, n: int):
        """
        Initializes a Recover object.

        Args:
            shares (List[Optional[bytes]]): A list of shares, where each share is an optional byte string.
            k (int): The minimum number of shares required to recover the secret.
            n (int): The total number of shares available.

        Returns:
            None
        """
        self.shares = shares
        self.k = k
        self.n = n
        self.validate_inputs()

    def validate_inputs(self):
        """
        Validates the inputs provided for secret recovery.

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

    def recover(self) -> List[bytes]:
        """
        Recovers the secret using the provided shares.

        Returns:
            List[bytes]: The recovered secret.

        Raises:
            ValueError: If the shares list size is not equal to n for k-of-n recovery,
                        or if there are not enough shares provided to retrieve the secret.
        """
        if self.k == 1:  # 1-of-n
            return [next(x for x in self.shares if x is not None)] * self.n
        elif self.k == self.n:  # n-of-n
            return self.shares
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

            new_shares = []

            for i in range(self.n):
                new_share = secrets.newShare(i + 1, formatted)
                components = secrets.extractShareComponents(new_share)
                if len(components.data) % 2 == 1:
                    components.data = '0' + components.data

                new_shares.append(bytes.fromhex(components.data))

            return new_shares