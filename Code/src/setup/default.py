DEFAULT_KDF = {
    "kdf": "argon2id",  # hkdf, pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id (default)
    "hkdfdigest": "sha256",  # sha1, sha256, sha384, or sha512
    "pbkdf2rounds": 310000,  # owasp recommendation
    "pbkdf2digest": "sha256",  # sha256 and sha512 are common; see crypto.getHashes() for options
    "bcryptrounds": 10,  # owasp recommendation
    "scryptcost": 16384,  # 2**14; scrypt paper recommendation
    "scryptblocksize": 8,  # recommended value
    "scryptparallelism": 1,  # disable parallelism
    "argon2time": 2,  # owasp recommendation
    "argon2mem": 24576,  # 24 MiB; slightly more than owasp recommendation
    "argon2parallelism": 1,  # disable parallelism
}

DEFAULT_KEY = {
    "size": 32  # key size (bytes); outputs 256-bit key by default
}

DEFAULT_PASSWORD = {
    "id": "password"
}

DEFAULT_QUESTION = {
    "id": "question"
}

DEFAULT_HOTP = {
    "id": "hotp",
    "hash": "sha1",  # required for Google Authenticator compatibility
    "digits": 6,  # most common choice
    "issuer": "MFKDF",
    "label": "mfkdf.com"
}

DEFAULT_TOTP = {
    "id": "totp",
    "hash": "sha1",  # required for Google Authenticator compatibility
    "digits": 6,  # required for Google Authenticator compatibility
    "step": 30,  # required for Google Authenticator compatibility
    "window": 87600,  # max window between logins, 1 month by default
    "issuer": "MFKDF",
    "label": "mfkdf.com"
}

DEFAULT_STACK = {
    "id": "stack",
    "kdf": "pbkdf2",
    "pbkdf2rounds": 1
}

DEFAULT_HMACSHA1 = {
    "id": "hmacsha1"
}
