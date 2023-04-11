from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def create_key_pair(name):
    # Generate a new RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537, # commonly used value for e
        key_size=2048 # size of the key in bits
    )
    public_key = private_key.public_key()

    # Serialize the private key to PEM format
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize the public key to PEM format
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write the keys to files
    with open(f"{name}_private_key.pem", "wb") as f:
        f.write(pem_private_key)
    with open(f"{name}_public_key.pem", "wb") as f:
        f.write(pem_public_key)