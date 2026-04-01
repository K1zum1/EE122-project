# EE122-project

Team Members:
Jay Chong
Qamil Mirza


Tools: Python / Mininet-WiFi / Scapy


1. Literature Survey
Modern vehicles rely on the Controller Area Network (CAN) bus for internal communication. However, CAN lacks basic security features like encryption and authentication, leaving vehicles vulnerable to packet injection and Man-in-the-Middle (MitM) attacks. Recent research suggests that transitioning to Automotive Ethernet combined with Software-Defined Networking (SDN) allows for more granular control. This project for EE122 will review existing literature on CAN bus vulnerabilities and the efficacy of SDN-based firewalls in high-speed in-vehicle environments.


2. Problem Statement and Evaluation
The primary challenge is the lack of isolation between infotainment systems (vulnerable to external networks) and critical Electronic Control Units (ECUs) like braking and steering.
Evaluation Plan:
Emulation: We will use Python and Mininet-WiFi to emulate an in-vehicle network topology consisting of multiple ECUs and an SDN controller.
Attack Scenario: We will simulate a "Malicious ECU" attempting to flood the network (DoS) or spoof safety-critical messages using Scapy.
Defense Mechanism: We will implement an Intrusion Detection System (IDS) at the SDN controller level that dynamically pushes Flow Rules to switches to drop malicious traffic in real-time.


3. Expected Insights and Recommendations
We aim to quantify the latency overhead introduced by the SDN controller when inspecting packets. The project will evaluate whether a centralized SDN architecture provides sufficient performance for real-time safety requirements while successfully mitigating common automotive cyber threats. The final report will provide recommendations on optimized flow-table management to balance security and speed.


Project Timeline
3/11: Proposal Submission (Today)
4/08: Completion of network emulation and baseline attack testing.
4/28: Poster presentation of IDS performance results.
5/10: Final Extended Abstract and code submission.


