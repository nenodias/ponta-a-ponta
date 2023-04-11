from cryptography.fernet import Fernet

# Generate a new AES key
key = Fernet.generate_key()

print(key)

# Create a Fernet instance with the key
fernet = Fernet(key)

# Encrypt a message
message = b"Hello, World!"
encrypted_message = fernet.encrypt(message)

# Decrypt the message
decrypted_message = fernet.decrypt(encrypted_message)

# Print the results
print(f"Original message: {message}")
print(f"Encrypted message: {encrypted_message}")
print(f"Decrypted message: {decrypted_message}")