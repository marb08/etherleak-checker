# etherleak-checker
This Python script helps to detect the Etherleak (CVE-2003-0001) vulnerability on a target host by analyzing the padding data in network packets. The script uses Scapy to send various types of requests (ICMP, ARP, or TCP) and checks if the responses contain any padding data that could potentially leak sensitive memory contents.
