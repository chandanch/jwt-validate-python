import os
import jwt
from dotenv import load_dotenv
import base64
import datetime
import time
from aadtoken import get_public_key

import calendar

load_dotenv()

public_key = os.environ.get('AD_PUB_KEY')

new_pub_key= "-----BEGIN CERTIFICATE-----\nMIIDBTCCAe2gAwIBAgIQH4FlYNA+UJlF0G3vy9ZrhTANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIyMDUyMjIwMDI0OVoXDTI3MDUyMjIwMDI0OVowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBDDCbY/cjEHfEEulZ5ud/CuRjdT6/yN9fy1JffjgmLvvfw6w7zxo1YkCvZDogowX8qqAC/qQXnJ/fl12kvguMWU59WUcPvhhC2m7qNLvlOq90yo+NsRQxD/v0eUaThrIaAveZayolObXroZ+HwTN130dhgdHVTHKczd4ePtDjLwSv/2a/bZEAlPys102zQo8gO8m7W6/NzRfZNyo6U8jsmNkvqrxW2PgKKjIS/UafK9hwY/767K+kV+hnokscY2xMwxQNlSHEim0h72zQRHltioy15M+kBti4ys+V7GC6epL//pPZT0Acv1ewouGZIQDfuo9UtSnKufGi26dMAzSkCAwEAAaMhMB8wHQYDVR0OBBYEFLFr+sjUQ+IdzGh3eaDkzue2qkTZMA0GCSqGSIb3DQEBCwUAA4IBAQCiVN2A6ErzBinGYafC7vFv5u1QD6nbvY32A8KycJwKWy1sa83CbLFbFi92SGkKyPZqMzVyQcF5aaRZpkPGqjhzM+iEfsR2RIf+/noZBlR/esINfBhk4oBruj7SY+kPjYzV03NeY0cfO4JEf6kXpCqRCgp9VDRM44GD8mUV/ooN+XZVFIWs5Gai8FGZX9H8ZSgkIKbxMbVOhisMqNhhp5U3fT7VPsl94rilJ8gKXP/KBbpldrfmOAdVDgUC+MHw3sSXSt+VnorB4DU4mUQLcMriQmbXdQc8d1HUZYZEkcKaSgbygHLtByOJF44XUsBotsTfZ4i/zVjnYcjgUQmwmAWD\n-----END CERTIFICATE-----"

client_id = '11d03a99-3f3e-4587-baf6-a4ba47356b7c'
tenant_id = '73ad6539-b4fe-429c-97b6-fbc1b6ada80b'
issuer = 'https://sts.windows.net/{tenant_id}/'.format(tenant_id=tenant_id)

token = os.environ.get('TEMP_TOKEN')

# Decode token
decoded = jwt.decode(token, key=base64.b64decode(public_key), algorithms=['RS256'], options={'verify_signature': False})

print('Decoded: {}'.format(decoded))

date = datetime.datetime.utcnow()
# print('Current Date time {}'.format(date));
expiry_date = date + datetime.timedelta(minutes=3);
# print('Time Delta {}'.format(expiry_date));

# Encode token based on data
payload = {
    'name': decoded['name'],
    'id': 222332,
    'roles': ['Admin'],
    'portfolio_access': [122,223, 333],
    'is_active': True,
    'iss': 'https://camer.maindenierapp.net/DFiod659039-994ff/',
    'exp': calendar.timegm(expiry_date.utctimetuple()),
    'iat': calendar.timegm(date.utctimetuple()),
    
}


token_headers = {
    "kid": "2ZQpJ3UpbjAYXYGaXEJl8lV0TOICTDEV",
    "nonce": "SSWUIPEXW2390DF",

}

jwt_private_key = os.environ.get('JWT_KEY')

# 1. Encode the private in ascii format
# encode_private_key_bytes = new_pub_key.encode('ascii')

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
# print('Decoding encoded token...')
try:
    enc_decode = jwt.decode(access_token, base64.b64decode(jwt_public_key), algorithms=['RS256'], options={"verify_signature": True})
    print('Decoded Token: {}'.format(enc_decode));
except jwt.ExpiredSignature:
    print('Signature expired')
