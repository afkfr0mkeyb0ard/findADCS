import ssl
import socket
import sys
from ipaddress import IPv4Network, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed
import OpenSSL.crypto

########################################################################
MAX_WORKERS = 20    # MAX CONCURRENT REQUESTS
VERBOSE = False     # False : TO DISPLAY ONLY OPEN PORTS
########################################################################

if len(sys.argv) <= 1 :
    print("[!] No parameter found. Aborting.")
    print("[!] Please provide an IP range or file.")
    print("[EXAMPLE] > python3 getCertIssuers.py 192.168.0.0/24")
    print("[EXAMPLE] > python3 getCertIssuers.py 192.168.0.123")
    print("[EXAMPLE] > python3 getCertIssuers.py IPS.txt")
    sys.exit()
    
arg = sys.argv[1]
print("*** Scanning range " + arg + " ***")

ports = [443,636,8443]

def getIPof(hostname):
	return socket.gethostbyname(hostname)

def scan_ip(ip_address):
	try : 
		if VERBOSE :
			print(f"[i] Scanning {ip_address}")

		for port in ports:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(0.2)
			result = sock.connect_ex((ip_address, port))
			if result == 0:
				cert = ssl.get_server_certificate((ip_address, port))
				x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
				print(f'[+] {ip_address}:{port} --> ISSUED BY --> {x509.get_issuer().get_components()}')
			else:
				if VERBOSE :
					print(f"[-] Port {ip_address}:{port} is closed/filtered")

	except Exception as e:
		if ' getaddrinfo failed' in str(e) :
			print(f'[-] Cannot resolve {ip_address}')
		elif 'UNEXPECTED_EOF_WHILE_READING' in str(e):
			print(f'[-] {ip_address}:{port} is open but got an error while reading cert')
		elif 'UNSUPPORTED_PROTOCOL' in str(e):
			print(f'[-] {ip_address}:{port} is open but got an SSL error')
		else:
			print(f'[-] {ip_address}:{port} is open but got an SSL error ('+str(e)+')')
	    

try:
	ip_address = ip_address(arg)
	scan_ip(str(ip_address))
except ValueError:
    try:
        network = IPv4Network(arg)
        ip_addresses = [str(ip) for ip in network]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            results = executor.map(scan_ip, ip_addresses)
    except ValueError:
        try:
            with open(arg) as f:
                ip_addresses = [line.strip() for line in f]
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    results = executor.map(scan_ip, ip_addresses)
        except FileNotFoundError:
            print(f"[-] {arg} is not a valid IP address, network in CIDR notation, or file")
            print("[-] Aborting...")
            sys.exit()
