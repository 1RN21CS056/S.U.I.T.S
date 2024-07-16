from threading import Thread
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def decrypt_message(encrypted_message, private_key_path):
    try:
        private_key = RSA.import_key(open(private_key_path).read())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_message = cipher_rsa.decrypt(encrypted_message)
        return decrypted_message
    except ValueError as e:
        print(f"Decryption error: {e}")
        return None
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return None

def handle_client(client_socket):
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if encrypted_message:
                print(f"Encrypted message received: {encrypted_message}")
                message = decrypt_message(encrypted_message, 'server_private.pem')
                if message:
                    print(f"Received: {message}")
                    broadcast_message(encrypted_message, client_socket)
                else:
                    print("Failed to decrypt message.")
        except Exception as e:
            print(f"Error in handle_client: {e}")
            break

def broadcast_message(message, client_socket):
    for client in clients:
        if client != client_socket:
            try:
                client.send(message)
            except Exception as e:
                print(f"Error broadcasting message: {e}")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 9999))
server_socket.listen(5)

clients = []

print("Server listening on port 9999")

while True:
    try:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        clients.append(client_socket)
        client_handler = Thread(target=handle_client, args=(client_socket,))
        client_handler.start()
    except Exception as e:
        print(f"Error accepting connection: {e}")