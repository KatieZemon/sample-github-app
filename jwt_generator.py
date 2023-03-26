#!/usr/bin/env python3
import os

import jwt
import time

PRIVATE_KEY_FILE_PATH = os.getenv('KEY_FILE_PATH', 'key.pem')  # This is a file. Should it be a secret or volume?
APP_ID = '309928'


def generate():
    # Open PEM
    with open(PRIVATE_KEY_FILE_PATH, 'rb') as pem_file:
        signing_key = jwt.jwk_from_pem(pem_file.read())

    payload = {
        # Issued at time
        'iat': int(time.time()),
        # JWT expiration time (10 minutes maximum)
        'exp': int(time.time()) + 600,
        # GitHub App's identifier
        'iss': APP_ID
    }

    # Create JWT
    jwt_instance = jwt.JWT()
    encoded_jwt = jwt_instance.encode(payload, signing_key, alg='RS256')

    return encoded_jwt


if __name__ == '__main__':
    print(f'JWT: {generate()}')
