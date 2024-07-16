import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt_message(message, public_key_path):
    recipient_key = RSA.import_key(open(public_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_message = cipher_rsa.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, private_key_path):
    private_key = RSA.import_key(open(private_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(encrypted_message).decode()
    return decrypted_message

def send_message():
    message = entry.get()
    encrypted_message = encrypt_message(message, 'client_public.pem')
    print(encrypted_message)
    client_socket.send(encrypted_message)
    chat_window.insert(tk.END, f"Me: {message}\n")
    entry.delete(0, tk.END)

def receive_messages():
    while True:
        encrypted_message = client_socket.recv(1024)
        if encrypted_message:
            message = decrypt_message(encrypted_message, 'client_private.pem')
            chat_window.insert(tk.END, f"Friend: {message}\n")

root = tk.Tk()
root.title("Client")

chat_window = scrolledtext.ScrolledText(root, width=50, height=20)
chat_window.pack(pady=10)

entry = tk.Entry(root, width=40)
entry.pack(side=tk.LEFT, padx=10)

send_button = tk.Button(root, text="Send", command=send_message)
send_button.pack(side=tk.LEFT)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('192.168.82.126', 9999))  # Replace 'server_ip_address' with the actual server IP address

receive_thread = Thread(target=receive_messages)
receive_thread.start()

root.mainloop()



