#!/usr/bin/env python
# coding: utf-8

# In[1]:


from scapy.all import *
import sys
import socket

def select_iface():
    iface_list = socket.if_nameindex() #함수를 호출하여 사용 가능한 네트워크 인터페이스 목록을 가져옴
    
    if len(iface_list) == 0: # 네트워크 인터페이스가 없을 경우 확인
        print("OH NO") # 네트워크 인터페이스가 없을 때 오류 메시지 출력
        sys.exit() # 오류 메시지 출력 후 프로그램 종료
        
    print("Available Network Interfaces:") # 사용 가능한 네트워크 인터페이스 목록 출력 
    for iface in iface_list:
        i, face = iface # iface의 첫번째 요소를 'i', 두번째 요소를 'face'
        print(f"{i}: {face}") # 사용 가능한 네트워크 인터페이스 목록 출력
        
    i = int(
            input(f"\nSelect network interface number to capture [1-{len(iface_list)}]: ")
        ) # 사용자로부터 네트워크 인터페이스 번호 입력 받음
    return iface_list[i-1][1]  # 선택한 네트워크 인터페이스 이름 반환

def process_packet(file_name, packet):
    wrpcap(filename= file_name, pkt = packet, append = True) # 패킷을 파일에 저장 (기존 파일에 추가)
    
def main():
    file_name = str(sys.argv[1]) # 명령줄 인수로 전달된 파일 이름 저장
    duration = int(sys.argv[2])  # 명령줄 인수로 전달된 지속 시간 저장
    
    iface= select_iface() # 사용자가 선택한 네트워크 인터페이스 이름 가져옴
    
    sniff(
            iface = iface,
            filter = "tcp or udp or icmp",  # TCP, UDP, ICMP 패킷만 캡처
            prn = lambda pkt: process_packet(file_name, pkt), # 패킷을 처리하는 함수 지정
            timeout=duration # 지속 시간 동안 패킷 캡처
    )

    print("DONE")
    print(f"{iface}에서 해써요! {duration}동안 캡쳐했어요! 그리고")
    print(f"{file_name}에 저장했어요~~~~")
    
if __name__ == "__main__":
    main()


# In[ ]:




