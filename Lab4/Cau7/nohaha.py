import socket

HOST = "0.tcp.ap.ngrok.io"  # The server's hostname or IP address
PORT = 17504  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    for i in range(100):
        s.send(b"i\n")
        data = s.recv(1024)
        
    s.close()

print(f"Received {data!r}")