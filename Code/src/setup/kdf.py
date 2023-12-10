import hashlib
import pbkdf2
import bcrypt
import scrypt
from argon2 import PasswordHasher
from hkdf import hkdf

async def kdf(input, salt, size, options):
    if isinstance(input, str):
        input = input.encode()
    if isinstance(salt, str):
        salt = salt.encode()

    if options['type'] == 'pbkdf2':
        return pbkdf2.pbkdf2_bin(input, salt, options['params']['rounds'], size, hashlib.new(options['params']['digest']).digest())
    elif options['type'] == 'bcrypt':
        input_hash = hashlib.sha256(input).digest().decode('base64')
        salt_hash = hashlib.sha256(salt).digest().decode('base64').replace('+', '.')
        hashed = bcrypt.hashpw(input_hash, '$2a$' + str(options['params']['rounds']) + '$' + salt_hash)
        derived_key = pbkdf2.pbkdf2_bin(hashed, salt_hash, 1, size, hashlib.sha256().digest())
        return derived_key
    elif options['type'] == 'scrypt':
        return scrypt.hash(input, salt, options['params']['rounds'], options['params']['blocksize'], options['params']['parallelism'], size)
    elif options['type'] in ['argon2i', 'argon2d', 'argon2id']:
        ph = PasswordHasher(
            time_cost=options['params']['rounds'],
            memory_cost=options['params']['memory'],
            parallelism=options['params']['parallelism'],
            hash_len=size
        )
        return ph.hash(input)
    elif options['type'] == 'hkdf':
        return hkdf(options['params']['digest'], input, salt, '', size)
    else:
        raise ValueError('kdf should be one of pbkdf2, bcrypt, scrypt, argon2i, argon2d, or argon2id (default)')
