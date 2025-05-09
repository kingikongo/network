import socket
import json
import time
import uuid

def get_ip_address():
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        temp_sock.connect(('8.8.8.8', 80))
        ip_address = temp_sock.getsockname()[0]
    except Exception as e:
        ip_address = '192.168.1.255'
       #ip_address = '127.0.0.1'

    finally:
        temp_sock.close()
    return ip_address


def service_announcer(username: str, port: int = 6000):
    presence_data = {"username": username, "ip_address": get_ip_address()}
    with open("self.json", "w") as f:
        json.dump(presence_data, f, indent=2)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    sock.settimeout(0.5)
    
    message = json.dumps(presence_data)

    message_bytes = message.encode()
    
    try:
        while True:

            sock.sendto(message_bytes, ('<broadcast>', port))
            print(f"'{message}': broadcast SUCCESSFUL")

            time.sleep(8)
    except Exception as e:
        print(f"An error occurred during broadcasting: {e}")
    except KeyboardInterrupt:
        print("\nService announcer stopped by user.")
    finally:
        sock.close()

def main():
    print("=== Starting announcement ===")
    print(" ") 
    username = input("Your username: ")
    print(" ")
    service_announcer(username)


if __name__ == "__main__":
    main()
