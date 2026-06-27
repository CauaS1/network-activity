from datetime import datetime
import mariadb

conn = mariadb.connect(
    user="root",
    password="1234567",
    database="soc_lab" # try deleting this line to see if i can create a logic to check the exitence of this db
)   

cursor = conn.cursor() # Tool that talks to the database


def eventLogger():
    cursor.execute("SELECT * from triggered_alerts")

    alerts = cursor.fetchall()

    for a in alerts:
        print(a)
eventLogger()

