import ssl
import socket
import sys
from ipaddress import IPv4Network, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed
import OpenSSL.crypto

########################################################################
MAX_WORKERS = 5    # MAX CONCURRENT REQUESTS
VERBOSE = False     # False : TO DISPLAY ONLY OPEN PORTS
########################################################################

arg = sys.argv[-1]
print("*** Scanning range " + arg + " ***")
ports = [443]


def getIPof(hostname):
	return socket.gethostbyname(hostname)

def scan_ip(ip_address):
	try : 
		if VERBOSE :
			print(f"-> Scanning {ip_address}")
		for port in ports:
			cert = ssl.get_server_certificate((ip_address, port))
			x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
			print(f'{ip_address}:{port} --> ISSUED FOR --> {x509.get_subject().get_components()}')
			print(f'{ip_address}:{port} --> ISSUED BY --> {x509.get_issuer().get_components()}')

	except Exception as e:
		if ' getaddrinfo failed' in str(e) :
			print(f'Cannot resolve {ip_address}')
	    

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
            print(f"{arg} is not a valid IP address, network in CIDR notation, or file")
            print("Aborting...")
            sys.exit()
