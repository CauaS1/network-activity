from scapy.all import *
from datetime import datetime



#packet = sniff(count=5)
#packet.summary()

def test():
    response = sr1(IP(dst="192.168.1.1") / ICMP())
    print('data')

    # Fixing the timestamp from the response
    fixedTime = datetime.fromtimestamp(response.time)
    print(fixedTime)

    # Separating the data in a list && adding a timestamp
    response = f"{response}"
    splitedResp = response.split()
    
    splitedResp.insert(0, fixedTime)

    # separating into variables the: timestamp, source ip, destination ip and protocol used
    timestp = splitedResp[0]
    src_ip = splitedResp[4]
    dst_ip = splitedResp[6]
    protoc = splitedResp[3]

    print('timestamp ', timestp)
    print('source ', src_ip)
    print('destination ', dst_ip)
    print('protocvol ', protoc)


test()
    


