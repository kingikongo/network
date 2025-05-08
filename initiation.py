import json
import time
import socket
import sys
from pyDes import des, PAD_PKCS5
import random
import os
import base64


P = 19  # Prime number
G = 2   # Generator

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
    peers_by_ip = {}
    try: 
        with open("peers.json", "r") as f:
            peers_by_ip = json.load(f)

    except (FileNotFoundError, json.JSONDecodeError):
        print("No peers found yet or error loading peers.json.")
        peers = {} # Ensure global peers is empty if file not found
        return

    online_users_list = []
    away_users_list = []
    now = time.time_ns()

    
    for ip_address, (username, timestamp) in peers_by_ip.items():

        peers[username] = ip_address
        if now - (15 * 60 * 1000000000) < timestamp: # Within the last 15 minutes
             if  now - (10 * 1000000000) < timestamp: # Within the last 10 seconds
                 online_users_list.append(f"{username} (Online)")
             else:
                 away_users_list.append(f"{username} (Away)")



    print("\nAvailable Users:")
    if not online_users_list and not away_users_list:
        print("No users found within the last 15 minutes.")
    else:
        for user_status in sorted(online_users_list) + sorted(away_users_list):
            print(user_status)



def chat():
 #   global peers

 #   print(f"Peers: {peers}")
 #   if len(peers) == 0:
 #       print("No peer is found. Try 'Users' to get the list of users.")
 #       return

 #   peer_username = input("\nUsername to chat: ")
 #   if peer_username not in peers:
 #       print(f"The username '{peer_username}' is invalid.")
 #       return

 #   peer_ip_address = peers[peer_username]
 #   port = 6001
 #   
 #   node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

 #   try:
 #       node_socket.connect((peer_ip_address, port))
 #   except Exception as e:
 #       print(f"Unable to connect to user {peer_username} at {peer_ip_address}:{port}, Error: {e}")
 #       return

 #   is_secure = input("Do you want secure connection? ").lower() in ("secure", "yes")

 #   shared_secret = None

 #   if is_secure:
 #       print("The message will be encrypted.")
 #       self_private_key = int(input("Please enter a number to be used as your private key for encryption: "))
 #       with open("key.txt", "w") as f:
 #           f.write(str(self_private_key))

 #       public_key = generate_key(P, G, self_private_key)

 #       print(f"Sending public key: {public_key}...")
 #       #message = json.dumps({"username": user["username"], "key": public_key})
 #       message = json.dumps({"key": public_key})
 #       node_socket.send(message.encode())

 #       rec_message = node_socket.recv(1024).decode()
 #       print(f"Got message in key exchange: {rec_message}")
 #       rec_message = json.loads(rec_message)
 #       peer_public_key = rec_message["key"]

 #       shared_secret = generate_shared_secret(peer_public_key, self_private_key, P)
 #       print("shared_secret")
 #       chat_message = input("Message: ")
 #       message_encrypted = encrypt(chat_message, shared_secret)
 #       message_encrypted_b64 = base64.b64encode(message_encrypted).decode()

 #       #data = json.dumps({"username": user["username"], "encrypted_message": message_encrypted_b64})
 #       data = json.dumps({"encrypted_message": message_encrypted_b64})
 #       print(f"Sending secure message: {data}")
 #       node_socket.send(data.encode())

 #   else:
 #       print("The message will be sent without encryption.")
 #       chat_message = input("Message: ")
 #       data = json.dumps({"unencrypted_message": chat_message})
 #       node_socket.send(data.encode())

 #   node_socket.close()



    global peers 
    global users

    try:
        print(f"Peers: {peers}") 
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
        except Exception as e: 
            print(f"Unable to connect to user {peer_username} at {peer_ip_address}:{port}. Error: {e}")
            return 

        is_secure = input("Do you want secure connection? ").lower() in ("secure", "yes")

        shared_secret = None 

        if is_secure:
            print("Secure connection requested.")
            try: 
                self_private_key = int(input("Please enter a number to be used as your private key for encryption: "))

                public_key = generate_key(P, G, self_private_key)

                key_exchange_message = json.dumps({"key": public_key})
                print(f"Sending public key: {key_exchange_message}...")
                node_socket.send(key_exchange_message.encode())

                rec_message_bytes = node_socket.recv(1024)
                if not rec_message_bytes:
                    print("Connection closed by peer during key exchange.")
                    node_socket.close()
                    return # Exit if peer closes during key exchange

                rec_message = rec_message_bytes.decode()
                print(f"Got message in key exchange: {rec_message}")
                rec_message_json = json.loads(rec_message)

                if "key" in rec_message_json:
                    peer_public_key = rec_message_json["key"]
                    shared_secret = generate_shared_secret(peer_public_key, self_private_key, P)
                    print("Shared secret generated.")
                else:
                    print("Received unexpected message during key exchange.")
                    node_socket.close()
                    return 

            except ValueError:
                print("Invalid input for private key.")
                node_socket.close()
                return 
            except json.JSONDecodeError:
                 print("Received invalid JSON during key exchange.")
                 node_socket.close()
                 return 
            except Exception as e:
                print(f"Error during secure key exchange: {e}")
                node_socket.close()
                return 

        print(f"Starting chat with {peer_username}. Type 'quit' to end.")
        while True:
            try: 
                chat_message = input("You: ")
                if chat_message.lower() == 'quit':
                    break 
                if is_secure and shared_secret is not None:
                    message_encrypted = encrypt(chat_message, shared_secret)
                    message_encrypted_b64 = base64.b64encode(message_encrypted).decode()
                    data_to_send = json.dumps({"username": user["username"], "encrypted message": message_encrypted_b64})
                    print(f"Sending secure message: {data_to_send}")
                    node_socket.send(data_to_send.encode())
                    log_message(peer_username, peer_ip_address, chat_message, "SENT")

                elif not is_secure:
                    data_to_send = json.dumps({"username": user["username"], "unencrypted_message": chat_message})
                    node_socket.send(data_to_send.encode())
                    log_message(peer_username, peer_ip_address, chat_message, "SENT")

                else:
                    print("Error: Secure connection not established.")
                    break 

            except Exception as e:
                print(f"Error sending message: {e}")
                break 

        print("Chat session ended.")
        node_socket.close()

    except Exception as e:
        print(f"An unexpected error occurred during chat initiation: {e}")
        # Ensure socket is closed even on unexpected errors
        # Check if node_socket was created and is still open before trying to close
        if 'node_socket' in locals() and isinstance(node_socket, socket.socket) and node_socket.fileno() != -1:
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
