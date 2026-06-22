from scapy.all import *
from datetime import datetime
import mariadb

conn = mariadb.connect(
    user="root",
    password="1234567",
    database="soc_lab" # try deleting this line to see if i can create a logic to check the exitence of this db
)   

cursor = conn.cursor() # Tool that talks to the database

def table_exists():
    cursor.execute("""
        SELECT EXISTS ( \
        SELECT 1 FROM INFORMATION_SCHEMA.TABLES \
        WHERE TABLE_SCHEMA = 'soc_lab' AND TABLE_NAME = 'network_events' \
        ) AS table_exists
    """)

    res = cursor.fetchall()
    res = res[0][0]

    if res == 0:
        cursor.execute("""CREATE TABLE network_events ( \
        packet INT AUTO_INCREMENT PRIMARY KEY, \
        timestamp VARCHAR(40),
        src_mac VARCHAR(20),
        dst_mac VARCHAR(20), 
        src_ip VARCHAR(15),
        dst_ip VARCHAR(15),
        protocol VARCHAR(8)) 
    """)


#packet = sniff(count=5)
#packet.summary()

def snifferFunction():
    # Sniffing the enp0s3 interface for IP packets, storing is true
    packets = sniff(iface="enp0s3", filter="ip", store=True, count=3) 
    protocol = ''

    # Fixing the timestamp from the response
    fixedTime = datetime.fromtimestamp(packets[1].time)

    
    le = len(packets)
    print(le)

    i = 0
    while i < le:
        # Converting the number related to the protocol to its formal name
        protoNum = packets[i][IP].proto

        if protoNum == 1:
            protocol = 'ICMP'
        elif protoNum == 6:
            protocol = 'TCP'
        elif protoNum == 17:
            protocol = 'TCP'

        timestp = str(fixedTime)
        src_mac = str(packets[i][Ether].src)
        dst_mac = str(packets[i][Ether].dst)
        src_ip = str(packets[i][IP].src)
        dst_ip = str(packets[i][IP].dst)
        protoc = str(protocol)

        # Inserting data into the database
            # You can use F-STRING to make the database unsafe for SQL Injection
        cursor.execute("""
        INSERT INTO network_events
        (timestamp, src_mac, dst_mac, src_ip, dst_ip, protocol)
            VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (timestp, src_mac, dst_mac, src_ip, dst_ip, protoc)
        )

        conn.commit() # Don't forget to commit the changes into the db

        i = i + 1

def packetFloodAlert():
    cursor.execute("""
    SELECT timestamp, src_ip from network_events
    """)

    val = cursor.fetchall()

    # Create a disctionary containing the IP and its packet timestamp 
    ipTimes = {}
    for timestamp, ip in val: 
        
        if ip not in ipTimes:
            ipTimes[ip] = []

        ipTimes[ip].append(timestamp)

    cursor.execute(
        "SELECT src_ip FROM network_events" 
    )

    srcIpsFromDB = set(cursor.fetchall())

    IpTimesSortedByHour = {}
    # { '1.1.1.1: { 3: 5 }} | means 5 packets were requests from IP 1.1.1.1 in the HOUR 3

    for s in srcIpsFromDB: # It will navigate throught the list of unique IPS and access the dictionary 
        tmList = ipTimes[s[0]] # the DIC contains the timestamp related to the IP, but it does not show the IP

        ip = s[0]

        if ip not in IpTimesSortedByHour:
            IpTimesSortedByHour[ip] = {} 


        for t in tmList: # it will go through each timestap of the corresponding list [tm1, tm2, tm3...]
            t1 = datetime.strptime(
                t,
                '%Y-%m-%d %H:%M:%S.%f'
            )

            timeByHour = t1.hour # Takes only the hour of each timestamp

        if timeByHour not in IpTimesSortedByHour[ip]:
            IpTimesSortedByHour[ip][timeByHour] = 0

        IpTimesSortedByHour[ip][timeByHour] += 1
          

    print(IpTimesSortedByHour)
    i = 0
   
    # Checks time difference - HERE FOR TESTS
    for i in range(len(val) -1):
        
        ip1 = val[i][1]

        t2 = datetime.strptime(
            val[i+1][0],
            '%Y-%m-%d %H:%M:%S.%f'
        )
        ip2 = val[i+1][1]

    # It takes the timestamp, strip down and see the difference of time between them
        
#    print(delta.total_seconds())

def artificialData():
    i = 0
    while (i < 6):
        cursor.execute("""
            INSERT INTO network_events
            (timestamp, src_mac, dst_mac, src_ip, dst_ip, protocol)
                VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (f'2026-06-21 14:14:{i}.430358', '11:22:27:61:6c:f9', '08:00:27:61:6c:f9', "192.168.1.15", "0.0.0..1", "TEST")
            )

        conn.commit() # Don't forget to commit the changes into

        i = i + 1
    



table_exists()
#snifferFunction()
#artificialData()
packetFloodAlert()
