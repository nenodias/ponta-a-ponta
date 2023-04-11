import base64
import json
import load_pemfile
from flask import Flask, request
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

'''
import create
create.create_key_pair('backend')
'''


pem_data = load_pemfile.load_pem_file('backend_public_key.pem')
private_data = load_pemfile.load_pem_file('backend_private_key.pem')

private_key = load_pem_private_key(private_data, password=None, backend=default_backend())

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello world"

@app.route("/get-key")
def get_key():
    return base64.b64encode(pem_data)

@app.route("/secret-message", methods=["POST"])
def secret_message():
    print("Secret message")
    public_key = request.headers.get('key')
    client_public_key = load_pem_public_key(base64.b64decode(public_key), backend=default_backend())
    dados = json.loads(request.json)
    encrypted_message = base64.b64decode(dados["zpk"])
    message_b64 = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aes_key = base64.b64decode(message_b64)
    aes_encrypt = Fernet(aes_key)
    aes_encrypted_message = aes_encrypt.encrypt(json.dumps({"message":"Hello world"}).encode('utf-8'))
    print(f'msg -> aes_crypted = {aes_encrypted_message}')
    print(f'msg -> aes_crypted -> base64 = {base64.b64encode(aes_encrypted_message)}')
    secret_message = client_public_key.encrypt(
        base64.b64encode(aes_encrypted_message), 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f'msg -> aes_crypted -> base64 -> rsa_public = {secret_message}')
    print(f'msg -> aes_crypted -> base64 -> rsa_public -> base64 = {base64.b64encode(secret_message)}')
    return base64.b64encode(secret_message)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

'''
msg -> aes_crypted -> base64 -> rsa_public -> base64
base64 -> rsa_public -> base64 -> aes_crypted -> msg
'''
