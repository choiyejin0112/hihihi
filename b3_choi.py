from scapy.all import *
import sys
import socket

def select_iface():
    iface_list = socket.if_nameindex()
    
    if len(iface_list) == 0:
        print("OH NO")
        sys.exit()
        
    print("Available Network Interfaces:")
    for iface in iface_list:
        i, face = iface
        print(f"{i}: {face}")
        
    i = int(
            input(f"\nSelect network interface number to capture [1-{len(iface_list)}]: ")
        )
    return iface_list[i-1][1]

def process_packet(file_name, packet):
    wrpcap(filename= file_name, pkt = packet, append = True)
    
def main():
    file_name = str(sys.argv[1])
    duration = int(sys.argv[2])
    
    iface= select_iface()
    
    sniff(
            iface = iface,
            filter = "tcp or udp or icmp",
            prn = lambda pkt: process_packet(file_name, pkt),
            timeout=duration
    )
    
    print("DONE")
    print(f"{iface}에서 해써요! {duration}동안 캡쳐했어요! 그리고")
    print(f"{file_name}에 저장했어요~~~~")
    
    
if __name__ == "__main__":
    main()
