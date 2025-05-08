import json
import socket
import time

def udp_listener(port: int = 6000):
    # Create the UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    
    # Set the socket to allow address reuse
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind the socket to the broadcast address and port
    sock.bind(('', port))
    
    print(f"PORT: {port}")
    
    peers = {}

    while True:
        try:
            data, addr = sock.recvfrom(1024)  # Buffer size is 1024 bytes
            message = data.decode('utf-8')
            message_json = json.loads(message)
            ip_address = message_json["ip_address"]
            username = message_json["username"]
            if addr[0] not in peers:
                peers[message_json["ip_address"]] = (username, time.time_ns())
                print(f"{username} ({message_json["ip_address"]}) is online.")
            else:
                peers[message_json["ip_address"]] = (peers[message_json["ip_address"]][0], time.time_ns())
            
            with open("peers.json", "w") as f:
                json.dump(peers, f, indent=3)

        except Exception as e:
            print(f"MSG RCV ERR: {e}")
        except KeyboardInterrupt:
            print("User interrupted listener.")
            break
        
    sock.close()

if __name__ == "__main__":
    udp_listener()
