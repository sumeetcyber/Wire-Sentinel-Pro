# Wire-Sentinel-Pro
- meaning: A guard that watches network traffic and detects leaks.
- It detects suspicious levels of randomness.
- Requires root priviledge
- Processes packets and sees if packets are IP, if they are: checks if TCP or UDP.
	-> currently does not do ARP, ethernet, and other link layers (to prioritze the most used IP)
- The wlan0 interface is sniffed and packets are given to the analyzer
- Calculate Shannon entropy
- Checks and scores requests
- Calculates probability of each character, and the formula is applied `Entropy = - Σ (p * log2(p))`
- So, if payload is long AND looks random,  the suspicion score is increased.
- High entropy flags:
	* JWT tokens
	* Base64 blobs
	* API keys
	* Session IDs
	* Random encrypted payload
- Previously was called Packet Inspector


WSP contains a python script and an HTML UI.
The .py contains flask, deque, scapy, layer identifier (IP/TCP/UDP).
Currently limited to 500 packet buffer, to keep memory usage desirable for testing and playing.
The HTML contains export settings, UI themes, and the dashboard table.


Running the program
- Change directory (cd) into the folder
- `sudo fuser -k 5000/tcp`
- Run `sudo python wire_sentinel_server.py`
- Open HTML
- Go to Google and Wikipedia
- My IP https://whatismyipaddress.com/
- Check others' IP: https://www.whatismyip.com/ip-whois-lookup/
