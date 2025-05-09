import json
import time
import socket
import sys
from pyDes import des, triple_des, PAD_PKCS5 
import random
import os
import base64
from datetime import datetime 

P = 19  
G = 2   

peers = {} 
user = {}  

def generate_key(p, g, private_key):
    """Generates a Diffie-Hellman public key."""
    public_key = (g ** private_key) % p
    return public_key

def generate_shared_secret(public_key, private_key, p):
    """Generates the Diffie-Hellman shared secret."""
    shared_secret = (public_key ** private_key) % p
    return shared_secret

def encrypt(plaintext, key):
    """Encrypts plaintext using Triple DES with a padded key derived from the shared secret."""

    try:
        key_bytes = key.to_bytes(8, 'big')
    except Exception as e:
        print(f"DEBUG (Encrypt Error): Error converting key to bytes: {e}")
        raise 

    try:
        padded_key = key_bytes.ljust(24, b'\0')
        # DEBUG: Print the padded key in hex to compare with responder
        #print(f"DEBUG (Initiator Encrypt): Padded key bytes (hex): {padded_key.hex()}")
    except Exception as e:
        print(f"DEBUG (Encrypt Error): Error padding key bytes: {e}")
        raise

    try:
        k = triple_des(padded_key, padmode=PAD_PKCS5) 
    except Exception as e:
        print(f"DEBUG (Encrypt Error): Error creating triple_des cipher: {e}")
        raise 

    # Ensure plaintext is bytes before encryption
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    try:
        encrypted_text = k.encrypt(plaintext)
        return encrypted_text
    except Exception as e:
        #print(f"DEBUG (Encrypt Error): Error during encryption: {e}")
        raise # Re-raise to see full traceback


def decrypt(ciphertext, key):

    try:
        # Convert the shared secret integer to bytes (e.g., 8 bytes)
        key_bytes = key.to_bytes(8, 'big')
    except Exception as e:
        #print(f"DEBUG (Decrypt Error): Error converting key to bytes: {e}")
        raise # Re-raise to see full traceback

    try:
        # Pad with null bytes to make it 24 bytes long for Triple DES key
        padded_key = key_bytes.ljust(24, b'\0')
        # DEBUG: Print the padded key in hex to compare with initiator
        #print(f"DEBUG (Initiator Decrypt): Padded key bytes (hex): {padded_key.hex()}")
    except Exception as e:
        #print(f"DEBUG (Decrypt Error): Error padding key bytes: {e}")
        raise # Re-raise to see full traceback

    try:
        # Use Triple DES (triple_des) with the padded key and specified padding mode
        k = triple_des(padded_key, padmode=PAD_PKCS5) # Corrected: use triple_des
    except Exception as e:
        #print(f"DEBUG (Decrypt Error): Error creating triple_des cipher: {e}")
        raise # Re-raise to see full traceback

    try:
        decrypted_text = k.decrypt(ciphertext)
        return decrypted_text
    except Exception as e:
        #print(f"DEBUG (Decrypt Error): Error during decryption: {e}")
        # Decryption often fails silently or with padding errors if key is wrong.
        # We'll catch specific pyDes errors if needed, but a general exception
        # here will indicate a problem during the decrypt call itself.
        raise # Re-raise to see full traceback


def users():
    """Displays the list of online and away users based on peers.json."""
    global peers
    peers_by_ip = {}
    try:
        # Load peers from the shared peers.json file
        with open("peers.json", "r") as f:
            peers_by_ip = json.load(f)

    except (FileNotFoundError, json.JSONDecodeError):
        print("No peers found yet or error loading peers.json.")
        peers = {} # Ensure global peers is empty if file not found or corrupted
        return

    online_users_list = []
    away_users_list = []
    now = time.time_ns() # Current time in nanoseconds

    # Update the global peers dictionary for chat lookup and categorize users by status
    peers.clear() # Clear previous entries to reflect current peers.json
    for ip_address, (username, timestamp) in peers_by_ip.items():
        peers[username] = ip_address # Store username: ip_address for chat lookup

        # Check if user is online (last seen within 10 seconds) or away (last seen within 15 mins but not 10 secs)
        if now - (15 * 60 * 1_000_000_000) < timestamp: # Within the last 15 minutes
             if  now - (10 * 1_000_000_000) < timestamp: # Within the last 10 seconds
                 online_users_list.append(f"{username} (Online)")
             else:
                 away_users_list.append(f"{username} (Away)")

    print("\nAvailable Users:")
    if not online_users_list and not away_users_list:
        print("No users found within the last 15 minutes.")
    else:
        # Print online users first, then away users, sorted alphabetically
        for user_status in sorted(online_users_list) + sorted(away_users_list):
            print(user_status)


def chat():
    """Initiates a chat session with a selected peer."""
    global peers
    global user # Ensure user is accessible globally

    try:
        # Check if there are any peers available to chat with
        if not peers: # Check if the dictionary is empty
            print("No peer is found. Try 'Users' to get the list of users.")
            return

        # Get the username of the peer to chat with
        peer_username = input("\nUsername to chat: ")
        if peer_username not in peers:
            print(f"The username '{peer_username}' is invalid.")
            return

        # Get the peer's IP address from the peers dictionary
        peer_ip_address = peers[peer_username]
        port = 6001 # TCP port for chat

        # Create a TCP socket
        node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Attempt to connect to the peer's responder
            print(f"Attempting to connect to {peer_username} at {peer_ip_address}:{port}...")
            node_socket.connect((peer_ip_address, port))
            print("Connection successful.")
        except Exception as e:
            print(f"Unable to connect to user {peer_username} at {peer_ip_address}:{port}. Error: {e}")
            return # Exit the chat function if connection fails

        # Ask the user if they want a secure connection
        is_secure = input("Do you want secure connection? ").lower() in ("secure", "yes")

        shared_secret = None # Initialize shared secret

        if is_secure:
            print("Secure connection requested.")
            try:
                # Get the user's private key for Diffie-Hellman
                self_private_key_input = input("Please enter a number to be used as your private key for encryption: ")
                self_private_key = int(self_private_key_input) # Convert input to integer

                # Generate the initiator's public key
                public_key = generate_key(P, G, self_private_key)

                # Prepare and send the initiator's public key in JSON format
                key_exchange_message = json.dumps({"key": public_key})
                print(f"Sending public key: {key_exchange_message}...")
                node_socket.send(key_exchange_message.encode())

                # Receive the responder's public key
                rec_message_bytes = node_socket.recv(1024)
                if not rec_message_bytes:
                    print("Connection closed by peer during key exchange.")
                    node_socket.close()
                    return # Exit if peer closes during key exchange

                rec_message = rec_message_bytes.decode()
                print(f"Got message in key exchange: {rec_message}")

                # Parse the received public key message
                rec_message_json = json.loads(rec_message)

                if "key" in rec_message_json:
                    peer_public_key = rec_message_json["key"]
                    # Calculate the shared secret using peer's public key and self private key
                    shared_secret = generate_shared_secret(peer_public_key, self_private_key, P)
                    # DEBUG: Print the calculated shared secret
                    #print(f"DEBUG (Initiator Chat): Calculated shared_secret: {shared_secret}")
                    print("Shared secret generated.")
                else:
                    print("Received unexpected message during key exchange.")
                    node_socket.close()
                    return # Exit if key exchange message is invalid

            except ValueError:
                print("Invalid input for private key. Please enter an integer.")
                node_socket.close()
                return # Exit on invalid private key input
            except json.JSONDecodeError:
                 print("Received invalid JSON during key exchange.")
                 node_socket.close()
                 return # Exit on invalid JSON during key exchange
            except Exception as e:
                print(f"Error during secure key exchange: {e}")
                node_socket.close()
                return # Exit on other key exchange errors

        # --- Message Sending Logic (for a single message) ---
        print(f"Starting chat with {peer_username}. Type your message and press Enter.")
        try:
            # Get the message input from the user
            chat_message = input("You: ")
            if chat_message.lower() == 'quit':
                print("Chat session ended")
                # No message is sent if user types quit here
                node_socket.close() # Close the connection
                return # Exit the chat function

            # Load self user data again before sending to ensure latest username is used
            # This addresses the issue where announcer might update self.json while initiator is running.
            # A more standard approach would be to restart initiator after changing username.
            # Keeping this line for now as per previous discussion to pick up live changes.
            user = load_self()
            # DEBUG: Print the username being used for sending
            #print(f"DEBUG (Initiator Chat): Sending message with username: {user.get('username', 'Username key missing')}")


            if is_secure and shared_secret is not None:
                # Encrypt the message using the shared secret
                message_encrypted = encrypt(chat_message, shared_secret)
                # Base64 encode the encrypted bytes for safe JSON transport
                message_encrypted_b64 = base64.b64encode(message_encrypted).decode()
                # DEBUG: Print raw encrypted bytes after encryption
                #print(f"DEBUG (Initiator Chat): Raw encrypted bytes (hex) after encrypt: {message_encrypted.hex()}")


                # Prepare the encrypted message in JSON format, including username
                data_to_send = json.dumps({"username": user["username"], "encrypted message": message_encrypted_b64})
                print(f"Sending secure message: {data_to_send}")
                # Send the encrypted message
                node_socket.send(data_to_send.encode())
                # Log the sent message
                log_message(peer_username, peer_ip_address, chat_message, "SENT")

            elif not is_secure:
                # Prepare the unencrypted message in JSON format, including username
                data_to_send = json.dumps({"username": user["username"], "unencrypted_message": chat_message})
                print(f"Sending unencrypted message: {data_to_send}")
                # Send the unencrypted message
                node_socket.send(data_to_send.encode())
                # Log the sent message
                log_message(peer_username, peer_ip_address, chat_message, "SENT")

            else:
                # Should not happen if connection is established and secure option was chosen
                print("Error: Secure connection not established after key exchange.")
                # Consider closing socket and returning here as well
                node_socket.close()
                return


        except Exception as e:
            print(f"Error sending message: {e}")
            # The finally block will execute after this except block
        finally:
            # Ensure the socket is closed after sending (or attempting to send) the message
            print("Chat session ended")
            node_socket.close() # Close the TCP session after sending one message

        # The function returns here after the finally block executes

    except Exception as e:
        # Catch any unexpected errors during the overall chat initiation process
        print(f"An unexpected error occurred during chat initiation: {e}")
        # Ensure socket is closed even on unexpected errors
        # Check if node_socket was created and is still open before trying to close
        if 'node_socket' in locals() and isinstance(node_socket, socket.socket) and node_socket.fileno() != -1:
             node_socket.close()


def log_message(to_username: str, to_ip: str, message: str, status: str):
    """Logs a sent message to the history.jsonl file."""
    try:
        with open("history.jsonl", "a") as f:
            # Log the message from the perspective of the initiator (the sender)
            # Include the 'to' information and the status ('SENT')
            data = {"to": to_username, "ip": to_ip, "message": message, "epoch_ns": time.time_ns(), "status": status}
            f.write(f"{json.dumps(data)}\n")
    except Exception as e:
        print(f"Error logging message to history.jsonl: {e}")


def history():
    """Displays the chat history from history.jsonl in a formatted way."""
    if not os.path.exists("history.jsonl"):
        print("No chat history found.")
        return

    print("\n=== Chat History ===")
    try:
        with open("history.jsonl", "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    # Format and print the log entry
                    timestamp_ns = data.get("epoch_ns")
                    # Convert nanoseconds timestamp to a readable format
                    if timestamp_ns:
                        try:
                            timestamp_sec = timestamp_ns / 1_000_000_000
                            dt_object = datetime.fromtimestamp(timestamp_sec)
                            formatted_timestamp = dt_object.strftime('%Y-%m-%d %H:%M:%S')
                        except (ValueError, TypeError):
                             formatted_timestamp = "Invalid Timestamp"
                    else:
                        formatted_timestamp = "Unknown Timestamp"

                    message = data.get("message", "No Message Content")
                    status = data.get("status", "UNKNOWN") # Get the status logged by log_message/dump_message

                    # Determine sender/receiver information based on log structure
                    # Logs from initiator (SENT) should have "to" and "status": "SENT"
                    # Logs from responder (RECEIVED) should have "from" and (ideally) "status": "RECEIVED"
                    # Based on spec 2.4.0-D, responder logs "SENT", so we infer RECEIVED if 'from' is present.
                    if "to" in data and status == "SENT": # Log from initiator (SENT)
                        username = data.get("to", "Unknown User")
                        ip_address = data.get("ip", "Unknown IP")
                        display_status = "SENT" # Display status as SENT
                        peer_info = f"To: {username} ({ip_address})"
                    elif "from" in data: # Log from responder (RECEIVED) - infer from 'from' key
                        username = data.get("from", "Unknown User")
                        ip_address = data.get("ip", "Unknown IP")
                         # Display status as RECEIVED, regardless of how responder logged it (spec 2.4.0-D conflict)
                        display_status = "RECEIVED"
                        peer_info = f"From: {username} ({ip_address})"
                    else:
                        # Handle log entries that don't fit expected format
                        username = "Unknown User"
                        ip_address = "Unknown IP"
                        display_status = "UNKNOWN"
                        peer_info = f"Peer: {username} ({ip_address})"


                    # Print the formatted history entry
                    print(f"[{formatted_timestamp}] {peer_info} [{display_status}]: {message}")

                except json.JSONDecodeError:
                    print(f"Error decoding JSON line in history: {line.strip()}")
                except Exception as e:
                    print(f"Error processing history line: {line.strip()} - {e}")

    except Exception as e:
         print(f"Error reading history.jsonl file: {e}")

    print("=== End of History ===")


def load_self():
    """Loads the current user's data from self.json."""
    try:
        with open("self.json", "r") as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print("Error: self.json not found. Have you run announcer.py to set up your user?")
        # Exit the program if self.json is not found, as initiator cannot function without it.
        sys.exit(1) # Use sys.exit for a clean exit
    except json.JSONDecodeError:
        print("Error: Could not decode self.json. File might be corrupted.")
        sys.exit(1) # Exit on corrupted self.json
    except Exception as e:
        print(f"An unexpected error occurred loading self.json: {e}")
        sys.exit(1) # Exit on other errors


def main():
    """Main function to run the Chat Initiator application."""
    global user
    # Load user data once when the application starts
    user = load_self()
    # DEBUG: Confirm user data loaded
    #print(f"DEBUG (Main): Loaded user data: {user}")


    while True:
        # Display the main menu and get user action
        action = input("\nSelect one of the options:\nUsers (0)\nChat (1)\nHistory (2)\nExit (3)\n ")

        # Validate user input
        while action.lower() not in ("users", "chat",  "history", "exit", "0", "1", "2", "3"):
            print("Invalid option. Please enter 0, 1, 2, or 3.")
            action = input("\nSelect one of the options:\nUsers (0)\nChat (1)\nHistory (2)\nExit (3)\n ")

        # Perform the selected action
        if action.lower() in ("users", "0"):
            users() # Call the users function to display available peers
        elif action.lower() in ("chat", "1"):
            chat() # Call the chat function to initiate a chat session
        elif action.lower() in ("history", "2"):
            history() # Call the history function to display chat history
        elif action in ("exit", "3"):
            print("Exiting Chat Initiator.")
            return # Exit the main function, terminating the program
        # The else case with raise ValueError() is removed as input is validated by the while loop


if __name__ == "__main__":
    main() # Run the main function when the script is executed directly
