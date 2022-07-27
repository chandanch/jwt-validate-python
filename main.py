import os
import jwt
from dotenv import load_dotenv
import base64
import datetime
import time

import calendar

load_dotenv()

public_key = os.environ.get('AD_PUB_KEY')

token = os.environ.get('TEMP_TOKEN')

# Decode token
decoded = jwt.decode(token, public_key, verify=False, algorithms=['RS256'])

# print('Decoded: {}'.format(decoded))

date = datetime.datetime.utcnow()
print('Current Date time {}'.format(date));
expiry_date = date + datetime.timedelta(minutes=3);
print('Time Delta {}'.format(expiry_date));

# Encode token based on data
payload = {
    'name': decoded['name'],
    'email': decoded['upn'],
    'id': 222332,
    'roles': ['Admin'],
    'portfolio_access': [122,223, 333],
    'is_active': True,
    'iss': 'https://camer.maindenierapp.net/DFiod659039-994ff/',
    'exp': calendar.timegm(expiry_date.utctimetuple()),
    'iat': calendar.timegm(date.utctimetuple()),
    'nbf': calendar.timegm(expiry_date.utctimetuple())
}


token_headers = {
    "kid": "2ZQpJ3UpbjAYXYGaXEJl8lV0TOICTDEV",
    "nonce": "SSWUIPEXW2390DF",

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

# Creates a access token
access_token = jwt.encode(payload=payload, key=base64.b64decode(jwt_private_key), algorithm='RS256', headers=token_headers)

print('Encoded: {}'.format(access_token))

## Decode encoded token
print('Decoding encoded token...')
try:
    enc_decode = jwt.decode(access_token, base64.b64decode(jwt_public_key), algorithms=['RS256'], options={"verify_signature": True})
    print('Decoded Token: {}'.format(enc_decode));
except jwt.ExpiredSignature:
    print('Signature expired')
