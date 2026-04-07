import socket
import time

HOST = "10.0.0.2"
PORT = 9999

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print(f"[victim] Listening on {HOST}:{PORT}")

count = 0
start = time.time()

while True:

    data, addr = sock.recvfrom(2048)
    count += 1

    if count % 100 == 0:
        elapsed = time.time() - start
        rate = count / elapsed if elapsed > 0 else 0
        print(f"[victim] received={count} avg_rate={rate:.2f} pkt/s last_from={addr}")
