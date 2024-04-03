import socket

def receive_udp_message(server_port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('0.0.0.0', server_port))
        print(f"UDP server listening on port {server_port}")

        while True:
            data, addr = sock.recvfrom(1024)
            message = data.decode('utf-8', errors='replace')
            print(f"Received message from {addr}: {message}")

if __name__ == "__main__":
    server_port = 2512  # Use the same port as in the lua_udp_sender.py script

    receive_udp_message(server_port)
