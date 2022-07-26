import os
import jwt
from dotenv import load_dotenv
import base64

load_dotenv()

public_key = os.environ.get('AD_PUB_KEY')

token = os.environ.get('TEMP_TOKEN')

# Decode token
decoded = jwt.decode(token, public_key, verify=False, algorithms=['RS256'])

# print('Decoded: {}'.format(decoded))

# Encode token based on data
payload = {
    'name': decoded['name'],
    'email': decoded['preferred_username'],
    'id': 222332,
    'roles': ['Admin'],
    'portfolio_access': [122,223, 333],
    'is_active': True
}


jwt_private_key = os.environ.get('JWT_KEY')

# 1. Encode the private in ascii format
# encode_private_key_bytes = encode_private_key.encode('ascii')

# 2. Encode it in base 64 format
# b64_ppk = base64.b64encode(encode_private_key_bytes)

# 3. Print out the base64 encoded string of the certificate
# print(b64_ppk)

# print(base64.b64decode(b64_ppk))


jwt_public_key = os.environ.get('JWT_PUB_KEY')


encoded = jwt.encode(payload=payload, key=base64.b64decode(jwt_private_key), algorithm='RS256')

print('Encoded: {}'.format(encoded))

## Decode encoded token
print('Decoding encoded token...')
enc_decode = jwt.decode(encoded, base64.b64decode(jwt_public_key), algorithms=['RS256'])
print('Decoded Token: {}'.format(enc_decode));