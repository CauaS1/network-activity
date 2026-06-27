from datetime import datetime
import logging
import mariadb

conn = mariadb.connect(
    user="root",
    password="1234567",
    database="soc_lab" # try deleting this line to see if i can create a logic to check the exitence of this db
)   

cursor = conn.cursor() # Tool that talks to the database

logging.basicConfig(
    filename="test.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
    
logger = logging.getLogger(__name__)

def eventLogger(src_mac, dst_mac, src_ip, dst_ip, protoc, level):   
 
    if level == "info":
        logging.info(f"{src_mac} -> {dst_mac} | {src_ip} -> {dst_ip} | {protoc}")
    elif level == "critical":
        logging.critical(f"{src_ip} was added to the BLACKLIST")

    #logging.info("Capturing Packets with MariaDB on enp0s3")

    #logging.warning("Packet flood detected")
    #logging.error("Could not connect to MariaDB")


    

