import json
import socket
import threading
import time
import base64

# Ensure triple_des is imported correctly
from pyDes import des, triple_des, PAD_PKCS5
import random

P = 19  # Prime number for Diffie-Hellman
G = 2   # Generator for Diffie-Hellman

def generate_key(p, g, private_key):
    public_key = (g ** private_key) % p
    return public_key

def generate_shared_secret(public_key, private_key, p):
    shared_secret = (public_key ** private_key) % p
    return shared_secret

def encrypt(plaintext, key):

    try:
        key_bytes = key.to_bytes(8, 'big')
    except Exception as e:
        #print(f"DEBUG (Encrypt Error - Responder): Error converting key to bytes: {e}")
        raise # Re-raise the exception

    try:
        padded_key = key_bytes.ljust(24, b'\0')
        # DEBUG: Print the padded key in hex
        #print(f"DEBUG (Responder Encrypt): Padded key bytes (hex): {padded_key.hex()}")
    except Exception as e:
        print(f"DEBUG (Encrypt Error - Responder): Error padding key bytes: {e}")
        raise # Re-raise the exception

    try:
        k = triple_des(padded_key, padmode=PAD_PKCS5) # Corrected: use triple_des
    except Exception as e:
        print(f"DEBUG (Encrypt Error - Responder): Error creating triple_des cipher: {e}")
        raise # Re-raise the exception

    # Ensure plaintext is bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    try:
        encrypted_text = k.encrypt(plaintext)
        return encrypted_text
    except Exception as e:
        print(f"DEBUG (Encrypt Error - Responder): Error during encryption: {e}")
        raise # Re-raise the exception


def decrypt(ciphertext, key):
    """Decrypts ciphertext using Triple DES with a padded key derived from the shared secret."""
    # key here is the shared_secret integer from Diffie-Hellman

    try:
        # Convert the shared secret integer to bytes (e.g., 8 bytes)
        key_bytes = key.to_bytes(8, 'big')
    except Exception as e:
        print(f"DEBUG (Decrypt Error - Responder): Error converting key to bytes: {e}")
        raise # Re-raise the exception

    try:
        # Pad with null bytes to make it 24 bytes long for Triple DES key
        padded_key = key_bytes.ljust(24, b'\0')
        # DEBUG: Print the padded key in hex
        #print(f"DEBUG (Responder Decrypt): Padded key bytes (hex): {padded_key.hex()}")
    except Exception as e:
        print(f"DEBUG (Decrypt Error - Responder): Error padding key bytes: {e}")
        raise # Re-raise the exception

    try:
        # Use Triple DES (triple_des) with the padded key and specified padding mode
        k = triple_des(padded_key, padmode=PAD_PKCS5) # Corrected: use triple_des
    except Exception as e:
        print(f"DEBUG (Decrypt Error - Responder): Error creating triple_des cipher: {e}")
        raise # Re-raise the exception

    try:
        decrypted_text = k.decrypt(ciphertext)
        return decrypted_text
    except Exception as e:
        print(f"DEBUG (Decrypt Error - Responder): Error during decryption: {e}")
        # Decryption often fails silently or with padding errors if key is wrong.
        # We'll catch specific pyDes errors if needed, but a general exception
        # here will indicate a problem during the decrypt call itself.
        raise # Re-raise the exception


def start_node(host="0.0.0.0", port=6001):
    """Starts the TCP server to listen for incoming chat connections."""
    node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set socket option to reuse address immediately
    node_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    node_socket.bind((host, port))
    node_socket.listen(5) # Listen for up to 5 incoming connections

    print(f"Responder listening to {host}:{port}")

    while True:
        try:
            # Accept incoming connection
            conn, addr = node_socket.accept()
            # DEBUG: Print accepted connection details
            print(f"Accepted connection from {addr[0]}")

        except Exception as e:
            print(f"Failed to accept connection: {e}")
            # Consider if you want to exit or continue the loop on accept errors
            continue # Continue listening for other connections

        # Start a new thread to handle the connection
        conn_thread = threading.Thread(target=handle_connection, kwargs={'conn': conn, 'addr': addr})
        conn_thread.start()


def handle_connection(conn, addr):
    """Handles a single incoming TCP connection."""
    print(f"\nConnected to {addr[0]}")
    # Removed the while flg_connection: loop to handle one message per connection as per spec.

    shared_secret = None # Initialize shared secret for this connection

    try:
        # Receive the first message (expected to be key exchange or initial message)
        rec_message_bytes = conn.recv(1024)
        if not rec_message_bytes:
            print(f"Peer at {addr[0]} closed the connection.")
            conn.close() # Close connection if no data is received
            return # Exit the handler for this connection

        rec_message = rec_message_bytes.decode()
        print(f"RCVD: {rec_message}")

        # Parse the received message as JSON
        try:
            rec_message_json = json.loads(rec_message)
        except json.JSONDecodeError:
            print(f"Error parsing JSON message from {addr[0]}: Invalid JSON")
            conn.close() # Close on parsing error
            return # Exit the handler
        except Exception as e:
            print(f"Error processing received message from {addr[0]}: {e}")
            conn.close() # Close on other processing errors
            return # Exit the handler


        # Handle message based on its content
        if "key" in rec_message_json:
            # Key exchange message received

            # load self private key from key.txt
            try:
                with open("key.txt", "r") as f:
                    self_private_key = int(f.read())
            except FileNotFoundError:
                 print("Error: key.txt not found. Cannot perform secure key exchange.")
                 conn.close()
                 return
            except ValueError:
                 print("Error: Invalid private key in key.txt. Must be an integer.")
                 conn.close()
                 return
            except Exception as e:
                 print(f"Error reading key.txt: {e}")
                 conn.close()
                 return

            # Generate the responder's public key
            self_public_key = generate_key(P, G, self_private_key)

            # Get the initiator's public key from the received message
            peer_public_key = rec_message_json["key"]

            # Generate the shared secret
            shared_secret = generate_shared_secret(peer_public_key, self_private_key, P)
            # DEBUG: Print the calculated shared secret
            #print(f"DEBUG (Responder Handle): Calculated shared_secret: {shared_secret}")
            print("Shared secret generated.")

            # Send the responder's public key back to the initiator
            message_to_send = json.dumps({"key": self_public_key})
            print(f"SENDING PUB KEY: {message_to_send}")
            conn.send(message_to_send.encode())

            # After key exchange, the next message should be the encrypted message.
            # We need to receive the actual chat message now.
            rec_message_bytes = conn.recv(1024)
            if not rec_message_bytes:
                print(f"Peer at {addr[0]} closed connection after key exchange.")
                conn.close()
                return

            rec_message = rec_message_bytes.decode()
            print(f"RCVD (after key exchange): {rec_message}")

            try:
                 rec_message_json = json.loads(rec_message)
            except json.JSONDecodeError:
                print(f"Error parsing JSON message after key exchange from {addr[0]}: Invalid JSON")
                conn.close()
                return
            except Exception as e:
                print(f"Error processing message after key exchange from {addr[0]}: {e}")
                conn.close()
                return


            # Now process the received message (expected to be encrypted or unencrypted)
            if "encrypted message" in rec_message_json:
                 # Proceed to decryption
                 pass # Continue to the decryption block below
            elif "unencrypted_message" in rec_message_json:
                 # Handle unencrypted message received after key exchange (unexpected but handle)
                 print("Warning: Received unencrypted message after secure key exchange.")
                 # Process as unencrypted message
                 print(f"[{rec_message_json['username']}]: {rec_message_json['unencrypted_message']}\n")
                 # Log the received unencrypted message
                 dump_message(from_username=rec_message_json["username"], from_ip=addr[0], message=rec_message_json["unencrypted_message"], epoch_ns=time.time_ns())
                 conn.close() # Close connection after handling
                 return # Exit handler


        # Handle encrypted message (either initial or after key exchange)
        if "encrypted message" in rec_message_json:
            if shared_secret is None:
                print("Error: Received encrypted message before shared secret was established.")
                conn.close()
                return # Exit handler if no shared secret

            try:
                # Base64 decode the encrypted message string
                received_message_encrypted_bytes = base64.b64decode(rec_message_json["encrypted message"])
                # DEBUG: Print bytes after base64 decode
                #print(f"DEBUG (Responder Handle): Bytes after base64 decode (hex): {received_message_encrypted_bytes.hex()}")

                # Decrypt the message bytes
                decrypted_text_bytes = decrypt(received_message_encrypted_bytes, shared_secret)
                 # DEBUG: Print raw decrypted bytes
                #print(f"DEBUG (Responder Handle): Raw decrypted bytes (hex): {decrypted_text_bytes.hex()}")
                #print(f"DEBUG (Responder Handle): Attempting to decode raw bytes...") # Marker before decode attempt

                # Decode the decrypted bytes to a string
                message = decrypted_text_bytes.decode()

                # Display the decrypted message
                print(f"[{rec_message_json.get('username', 'Unknown User')}]: {message}\n") # Use .get for safety
                # Log the received decrypted message
                dump_message(from_username=rec_message_json.get("username", "Unknown User"), from_ip=addr[0], message=message, epoch_ns=time.time_ns())

            except base64.Error as e:
                print(f"Error Base64 decoding encrypted message: {e}")
            except Exception as e:
                print(f"Error decrypting or decoding message: {e}")
                # Decryption often fails with padding errors if key is wrong.
                # A more specific pyDes exception catch could be added here if needed.

            # Connection is closed by initiator after sending the message.
            # The thread will naturally exit after processing this message.


        # Handle unencrypted message (if received initially)
        elif "unencrypted_message" in rec_message_json:
            # Display the unencrypted message
            print(f"[{rec_message_json.get('username', 'Unknown User')}]: {rec_message_json['unencrypted_message']}\n") # Use .get for safety
            # Log the received unencrypted message
            dump_message(from_username=rec_message_json.get("username", "Unknown User"), from_ip=addr[0], message=rec_message_json["unencrypted_message"], epoch_ns=time.time_ns())

            # Connection is closed by initiator after sending the message.
            # The thread will naturally exit after processing this message.

        else:
            # Handle unexpected message format
            print(f"Received message with unexpected format from {addr[0]}: {rec_message_json}")

    except Exception as e:
        # Catch any other unexpected errors during connection handling
        print(f"An unexpected error occurred while handling connection from {addr[0]}: {e}")

    finally:
        # Ensure the connection is closed when the handler finishes
        # This is important if the initiator doesn't close it, or on errors.
        # However, if the initiator *is* closing after sending, this might
        # sometimes try to close an already closed socket. A check like
        # if conn.fileno() != -1: conn.close() could be added if needed.
        conn.close()
        print(f"Connection closed with {addr[0]}")


def dump_message(from_username: str, from_ip: str, message: str, epoch_ns: int):
    """Logs a received message to the history.jsonl file."""
    try:
        with open("history.jsonl", "a") as f:
            # Log the message as required by 2.4.0-D, including status "SENT" (as per spec)
            # Note: The history display logic will interpret this as "RECEIVED".
            data = {"from": from_username, "ip": from_ip, "message": message, "epoch_ns": epoch_ns, "status": "SENT"} # Added status field
            f.write(f"{json.dumps(data)}\n")
    except Exception as e:
        print(f"Error logging message to history.jsonl: {e}")


if __name__ == "__main__":
    start_node() # Run the main responder function when the script is executed directly
