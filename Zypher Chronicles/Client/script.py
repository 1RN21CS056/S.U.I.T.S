# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP

# # Generate RSA key pair (public/private keys)
# key = RSA.generate(2048)

# # Get public and private keys
# public_key = key.publickey()
# private_key = key

# # Example data to encrypt
# data = b"Hello World"

# # Encryption using the public key 
# cipher_rsa = PKCS1_OAEP.new(public_key)
# encrypted_data = cipher_rsa.encrypt(data)

# # Decryption using the private key
# cipher_rsa = PKCS1_OAEP.new(private_key)
# decrypted_data = cipher_rsa.decrypt(encrypted_data)

# # Print results
# print("Original data:", data.decode('utf-8'))
# print("Encrypted data:", encrypted_data)
# print("Decrypted data:", decrypted_data.decode('utf-8'))

from Crypto.PublicKey import RSA

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open('client_private.pem', 'wb') as f:
        f.write(private_key)
    with open('client_public.pem', 'wb') as f:
        f.write(public_key)

generate_keys()