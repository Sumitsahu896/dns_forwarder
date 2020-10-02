import socket
from scapy.all import *
from scapy.layers.dns import DNS
import http.client
import requests
import os
import sys
import base64
import argparse
import subprocess

def check_names(path):
	return os.path.isdir(path)

def runDNSServer(args):
    SERVER_IP = '127.0.0.1'
    SERVER_PORT = 53
    DNS_Resolver = args.DST_IP # default is 8.8.8.8
    Doh_required = False        #Default
    LOG_FILE = args.LOG_FILE    #default is False
    query_type = 'A'
    DENY_LIST = args.DENY_LIST_FILE #default is False
    PERMISSION = 'ALLOW'

    if args.DOH_Required:
        Doh_required = True
        DOH_Resolver = 'dns.google'
    
    if args.DOH_SERVER:
        Doh_required = True
        DOH_Resolver = args.DOH_SERVER
    

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP,SERVER_PORT))

    while True:
        d, client_addr = sock.recvfrom(1024)
        client_payload = DNS(d) 

        query = client_payload[DNS].qd.qname 
        query = query.decode('utf-8')
        query = query.rstrip('.')

        if DENY_LIST:
            with open(DENY_LIST, 'r') as r:
                lines = r.readlines()
                
            r.close()        
        
            for i in range(len(lines)):
                if query == lines[i]:
                    PERMISSION = 'DENY'
                else:
                    PERMISSION = 'ALLOW'
            

        if PERMISSION == 'DENY':
            client_payload.rcode = 3
            client_payload.qr = 1
            print("Domain name not allowed!")
            sock.sendto(bytes(client_payload),client_addr)
            if query_type == True:
                query_type = client_payload[DNS].qd.qtype
                query_type = dnsqtypes[query_type]


        if PERMISSION == 'ALLOW':
            if Doh_required == False:
                
                try:
                    response = sr1(IP(dst=DNS_Resolver)/UDP(dport=SERVER_PORT)/DNS(id=client_payload.id, rd=1, qd=DNSQR(qname=query)))
                    sock.sendto(bytes(response[DNS]), client_addr)
                except:
                    print(f'{DNS_Resolver} is not valid!')

                if query_type == True:
                    query_type = response[DNS].qd.qtype
                    query_type = dnsqtypes[query_type]                
            else:
                encoded = base64.urlsafe_b64encode(bytes(client_payload[DNS]))
                encoded = encoded.decode('utf-8').strip().rstrip('=')

                url = 'https://' + DOH_Resolver + '/dns-query?dns=' + encoded

                try:
                    doh_response = requests.get(url=url)
                    response_raw_packet = doh_response.content
                    resp = DNS(response_raw_packet)
                    resp.id = client_payload.id
                    sock.sendto(bytes(resp), client_addr)
                    if query_type == True:
                        query_type =resp[DNS].qd.qtype
                        query_type = dnsqtypes[query_type]

                except:
                    print(f'{DOH_Resolver} is not a valid doh server!')
                    client_payload.rcode = 3
                    client_payload.qr = 1
                    sock.sendto(bytes(client_payload),client_addr)
                    if query_type == True:
                        query_type = client_payload[DNS].qd.qtype
                        query_type = dnsqtypes[query_type]



        log_entry = f'{query} {query_type} {PERMISSION}\n'

        if LOG_FILE:
            with open(LOG_FILE, 'a') as f: 
                f.write(log_entry)
            f.close()


def main():
    parser = argparse.ArgumentParser(description="DoH-capable DNS forwarder with domain blocking")
    parser.add_argument("-d", help="Destination DNS server IP", dest="DST_IP",type=str,default='8.8.8.8',required=False)
    parser.add_argument("-f", help="File containing domains to block", dest="DENY_LIST_FILE",type=str,required=False,default=False)
    parser.add_argument("-l", help="Append-only log file", dest="LOG_FILE",type=str,required=False,default=False)
    parser.add_argument("--doh", help="Use default upstream DoH server",action='store_true',dest="DOH_Required",required=False)
    parser.add_argument("--doh_server", help="Use this upstream DoH server", dest="DOH_SERVER",type=str,default=False,required=False)
    parser.set_defaults(func=runDNSServer)
    args=parser.parse_args()
    args.func(args)

if __name__=="__main__":
	main()

