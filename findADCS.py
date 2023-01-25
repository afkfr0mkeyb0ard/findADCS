import socket
import argparse
import sys
import ipaddress
import requests

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
parser.add_argument('target') 
parser.add_argument("-p",help="Ports to scan (default 80,443)", default="80,443",metavar='')
group.add_argument("-H",help="If your target is a hostname (ie dc-01.local)",action='store_true')
group.add_argument("-F",help="If your targets are in a file (one per line) (ie /tmp/targets.txt)",action='store_true')
group.add_argument("-I",help="If your target is an IP address (ie 10.10.0.2)",action='store_true')
group.add_argument("-R",help="If your target is a range of IP (ie 10.10.10.0/24)",action='store_true')
parser.parse_args()

args = parser.parse_args()

if not args.H and not args.F and not args.I and not args.R :
	print("Please specify a mode for your target (--help for examples)")
	sys.exit()

# remoteServerIP  = socket.gethostbyname(remoteServer) # get IP from host

def main():
	TARGETS = getTargets(args)   # can be an IP, a hostname, a range of IP (10.10.10.0/24), or a file
	PORTS = getPorts(args)

	for target in TARGETS :
		print("Trying " + target)
		for port in PORTS :
			sock = sendSocket(target,port)
			if sock == 0 and port == str(80) :
				print(target + ":" + port + " -> OPEN !")
				url = "http://" + target + "/certsrv/certfnsh.asp"
				r = requests.get(url)
				if r.status_code == 401 :
					print("ADCS FOUND ! -> " + url)
			elif sock == 0 and port == str(443) :
				print(target + ":" + port + " -> OPEN !")
				url = "https://" + target + "/certsrv/certfnsh.asp"
				r = requests.get(url,verify=False)
				if r.status_code == 401 :
					print("ADCS FOUND ! -> " + url)
			elif sock == 0 :
				print(target + ":" + port + " -> OPEN !")
				url = "http://" + target + ":" + port + "/certsrv/certfnsh.asp"
				r = requests.get(url,verify=False)
				if r.status_code == str(401) :
					print("ADCS FOUND ! -> " + url)

				

def getTargets(args):
	if args.H :
		print("Will target ")
		return [getIPof(args.target)]

	elif args.I :
		print("I")
		return [args.target]

	elif args.R:
		print("R")
		network = ipaddress.ip_network(args.target)
		hosts = network.hosts()
		ips = []
		for h in hosts :
			ips.append(str(h))
		return ips

	elif args.F :
		print("F")
		f = open(args.target,'r')
		lines = file.read().splitlines()
		ips = []
		for el in lines :
			try :
				ipaddress.ip_address(el)
				ips.append(el)
			except ValueError :
				ips.append(getIPof(el))
		return ips


def getPorts(args):
	return args.p.split(",")

def getIPof(hostname):
	return socket.gethostbyname(hostname)

def sendSocket(target,port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	socket.setdefaulttimeout(0.5)
	result = sock.connect_ex((target, int(port)))
	sock.close()
	return result


if __name__ == '__main__':
	main()