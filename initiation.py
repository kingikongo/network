import json
import time
import socket
import sys
from pyDes import des, PAD_PKCS5
import random
import os
import base64


P = 23  # Prime number
G = 5   # Generator

peers = {}
user = {}

def generate_key(p, g, private_key):
    public_key = (g ** private_key) % p
    return public_key

def generate_shared_secret(public_key, private_key, p):
    shared_secret = (public_key ** private_key) % p
    return shared_secret

def encrypt(plaintext, key):
    k = des(key.to_bytes(8, 'big'), padmode=PAD_PKCS5)
    encrypted_text = k.encrypt(plaintext)
    return encrypted_text

def decrypt(ciphertext, key):
    k = des(key.to_bytes(8, 'big'), padmode=PAD_PKCS5)
    decrypted_text = k.decrypt(ciphertext)
    return decrypted_text

def users():
    global peers
    with open("peers.json", "r") as f:
        peers = json.load(f)
    
    for k, v in peers.copy().items():
        ip_address = k
        username = v[0]
        timestamp = v[1]
        now = time.time_ns()
        peers[username] = ip_address
        if now - (15 * 60 * 1000000000) < timestamp:  # 15 minutes
            if now - (10 * 1000000000) < timestamp: # 10 seconds:
                print(f"{username} (Online)")
            else:
                print(f"{username} (Away)")
        else:
            print(f"{username} (Offline)")



def chat():
    if len(peers) == 0:
        print("No peer is found. Try 'Users' to get the list of users.")
        return

    peer_username = input("\nUsername to chat: ")
    if peer_username not in peers:
        print(f"The username '{peer_username}' is invalid.")
        return

    peer_ip_address = peers[peer_username]
    port = 6001
    
    node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        node_socket.connect((peer_ip_address, port))
    except:
        print(f"Unable to connect to user {peer_username}...")
        return

    is_secure = input("Do you want secure connection? ").lower() in ("secure", "yes")

    if is_secure:
        print("The message will be encrypted.")
        self_private_key = int(input("Please enter a number to be used as your private key for encryption: "))
        with open("key.txt", "w") as f:
            f.write(str(self_private_key))

        public_key = generate_key(P, G, self_private_key)

        print(f"Sending public key: {public_key}...")
        message = json.dumps({"username": user["username"], "key": public_key})
        node_socket.send(message.encode())

        rec_message = node_socket.recv(1024).decode()
        print(f"Got message in key exchange: {rec_message}")
        rec_message = json.loads(rec_message)
        peer_public_key = rec_message["key"]

        shared_secret = generate_shared_secret(peer_public_key, self_private_key, P)

        chat_message = input("Message: ")
        message_encrypted = encrypt(chat_message, shared_secret)
        message_encrypted_b64 = base64.b64encode(message_encrypted).decode()

        data = json.dumps({"username": user["username"], "encrypted_message": message_encrypted_b64})
        print(f"Sending secure message: {data}")
        node_socket.send(data.encode())

    else:
        print("The message will be sent without encryption.")
        chat_message = input("Message: ")
        data = json.dumps({"username": user["username"], "unencrypted_message": chat_message})
        node_socket.send(data.encode())

    node_socket.close()

def history():
    if not os.path.exists("history.jsonl"):
        print("No chat history found.")
        return

    with open("history.jsonl", "r") as f:
        for line in f:
            data = json.loads(line)
            print(data)
    
def load_self():
    try:
        with open("self.json", "r") as f:
            data = json.load(f)
        return data
    except:
        print("Unable to load self data. Have you started 'service_announcer'?")
        sys.close()

def main():
    global user
    user = load_self()

    while True:
        action = input("\nSelect one of the options:\nUsers (0)\nChat (1)\nHistory (2)\nExit (3)\n ")
        while action.lower() not in ("users", "chat",  "history", "exit", "0", "1", "2", "3"):
            action = input("\nSelect one of the options:\nUsers (0)\nChat (1)\nHistory (2)\nExit (3)\n ")
        
        if action.lower() in ("users", "0"):
            users()
        elif action.lower() in ("chat", "1"):
            chat()
        elif action.lower() in ("history", "2"):
            history()
        elif action in ("exit", "3"):
            return
        else:
            raise ValueError()


if __name__ == "__main__":
    main()
