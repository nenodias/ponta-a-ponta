import base64
import json
import requests as r
import load_pemfile
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

'''
import create
create.create_key_pair('client')
'''

aes_key = Fernet.generate_key()

pem_data = load_pemfile.load_pem_file('client_public_key.pem')
private_data = load_pemfile.load_pem_file('client_private_key.pem')

private_key = load_pem_private_key(private_data, password=None, backend=default_backend())

#public_key = load_pem_public_key(pem_data)

base_url = 'http://localhost:5000'

key = base64.b64encode(pem_data)

backend_b64_key = base64.b64decode(r.get(f'{base_url}/get-key').text)
backend_public_key = load_pem_public_key(backend_b64_key, backend=default_backend())
encrypted_aes_key = backend_public_key.encrypt(
    base64.b64encode(aes_key), 
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

headers = { "key": key }
dados = {
    "zpk":base64.b64encode(encrypted_aes_key).decode('utf-8')
}


resp = r.post(f'{base_url}/secret-message', json=json.dumps(dados), headers=headers)
print(f'base64 = {resp.text}')
print(f'base64 -> rsa_public = {base64.b64decode(resp.text)}')
message_b64 = private_key.decrypt(
    base64.b64decode(resp.text),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(f'base64 -> rsa_public -> base64 = {message_b64}')
print(f'base64 -> rsa_public -> base64 -> aes_crypted = {base64.b64decode(message_b64)}')

aes_encrypt = Fernet(aes_key)

secret_message = base64.b64decode(message_b64)
print(aes_encrypt.decrypt(secret_message))
'''
msg -> aes_crypted -> base64 -> rsa_public -> base64
base64 -> rsa_public -> base64 -> aes_crypted -> msg
'''

