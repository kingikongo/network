import json
import socket
import threading
import time
import base64


from pyDes import des, triple_des, PAD_PKCS5
import random

P = 19  # Prime number
G = 2   # Generator

def generate_key(p, g, private_key):
    public_key = (g ** private_key) % p
    return public_key

def generate_shared_secret(public_key, private_key, p):
    shared_secret = (public_key ** private_key) % p
    return shared_secret

#def encrypt(plaintext, key):
#    k = des(key.to_bytes(8, 'big'), padmode=PAD_PKCS5)
#    encrypted_text = k.encrypt(plaintext)
#    return encrypted_text
#
#def decrypt(ciphertext, key):
#    k = des(key.to_bytes(8, 'big'), padmode=PAD_PKCS5)
#    decrypted_text = k.decrypt(ciphertext)
#    return decrypted_text

def encrypt(plaintext, key):

    key_bytes = key.to_bytes(8, 'big')
    padded_key = key_bytes.ljust(24, b'\0')
    print(f"DEBUG (Responder): Padded key bytes: {padded_key}") # Add this line
    k = triple_des(padded_key, padmode=PAD_PKCS5) 

    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    encrypted_text = k.encrypt(plaintext)
    return encrypted_text

def decrypt(ciphertext, key):

    try:
        key_bytes = key.to_bytes(8, 'big')
        padded_key = key_bytes.ljust(24, b'\0')
        print(f"DEBUG (Responder): Padded key bytes (hex): {padded_key.hex()}") # Add this line (print as hex for clarity)
        k = triple_des(padded_key, padmode=PAD_PKCS5)

        decrypted_text = k.decrypt(ciphertext)
        return decrypted_text
    except Exception as e:
        print(f"Error in decrypt function: {e}")

def start_node(host="0.0.0.0", port=6001):
    node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    node_socket.bind((host, port))
    node_socket.listen(1)

    print(f"Responder listening to {host}:{port}")

    while True:
        try:
            conn, addr = node_socket.accept()
        except:
            print("Failed to accept connection")
            print(f"conn: {conn}")
            print(f"addr: {addr}")
            return

        conn_thread = threading.Thread(target=handle_connection, kwargs={'conn': conn, 'addr': addr})
        conn_thread.start()


def handle_connection(conn, addr):
    print(f"\nConnected to {addr[0]}")
    flg_connection = True

    while flg_connection:
        try:
            rec_message = conn.recv(1024).decode()
            if not rec_message:
                break

            print(f"RCVD: {rec_message}")
            rec_message = json.loads(rec_message)
        except json.JSONDecodeError:
            print("Error receiving/parsing the message")
            continue
        except Exception as e:
            print(f"Error receiving/parsing the message: {e}")
            raise

        if "key" in rec_message:
            # load self key
            with open("key.txt", "r") as f:
                self_private_key = int(f.read())
            self_public_key = generate_key(P, G, self_private_key)

            # exchange key ...
            peer_public_key = rec_message["key"]
            # generate shared secrect
            shared_secret = generate_shared_secret(peer_public_key, self_private_key, P)
            print(f"DEBUG (Responder): Calculated shared_secret: {shared_secret}") 

            message = json.dumps({"key": self_public_key})
            print(f"SENDING PUB KEY: {message}")
            conn.send(message.encode())

        elif "encrypted_message" in rec_message:
            received_message_encrypted_bytes = base64.b64decode(rec_message["encrypted_message"])
            decrypted_text_bytes = decrypt(received_message_encrypted_bytes, shared_secret)

            print(f"DEBUG (Responder Handle): Raw decrypted bytes (hex): {decrypted_text_bytes.hex()}") # Debug print
            print(f"DEBUG (Responder Handle): Attempting to decode raw bytes...") 
            message = decrypt(received_message_encrypted_bytes, shared_secret).decode()
            print(f"[{rec_message['username']}]: {message}\n")
            dump_message(from_username=rec_message["username"], from_ip=addr[0], message=message, epoch_ns=time.time_ns())
            flg_connection = False

        elif "unencrypted_message" in rec_message:
            print(f"[{rec_message['username']}]: {rec_message['unencrypted_message']}\n")
            dump_message(from_username=rec_message["username"], from_ip=addr[0], message=rec_message["unencrypted_message"], epoch_ns=time.time_ns())
            flg_connection = False
    
    conn.close()

def dump_message(from_username: str, from_ip: str, message: str, epoch_ns: int):
    with open("history.jsonl", "a") as f:
        data = {"from": from_username, "ip": from_ip, "message": message, "epoch_ns": epoch_ns, "status": "SENT"} 
        f.write(f"{json.dumps(data)}\n")

if __name__ == "__main__":
    start_node()
