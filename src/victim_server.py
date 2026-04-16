import socket
import time
import yaml
from pathlib import Path

config_path = Path(__file__).parent / "config.yaml"
with open(config_path) as f:
    cfg = yaml.safe_load(f)

HOST = cfg["network"]["victim_ip"]
PORT = cfg["victim"]["listen_port"]
LOG_INTERVAL = cfg["victim"]["log_interval"]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print(f"[victim] Listening on {HOST}:{PORT}")

count = 0
start = time.time()

while True:
    data, addr = sock.recvfrom(2048)
    count += 1

    if count % LOG_INTERVAL == 0:
        elapsed = time.time() - start
        rate = count / elapsed if elapsed > 0 else 0
        print(f"[victim] received={count} avg_rate={rate:.2f} pkt/s last_from={addr}")
