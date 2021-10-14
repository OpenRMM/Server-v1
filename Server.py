#!/usr/bin/env python3

import os
import paho.mqtt.client as mqtt
import json
import time
import subprocess
import threading
import mysql.connector
import datetime

################################# SETUP ##################################
MQTT_Server = "*******"
MQTT_Username = "*******"
MQTT_Password = "*******"
MQTT_Port = 1884
MQTT_Topic = "#"

MYSQL_Server = "*******"
MYSQL_Username = "*******"
MYSQL_Password = "*******"
MYSQL_Port = 3306
MYSQL_Database = "OpenRMM"

Server_Version = "1.0"

LOG_File = "C:\OpenRMMServer.log"
DEBUG = False

###########################################################################

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    log("MQTT connected with result code: " + str(rc), "")
    if (rc==0):
        mqtt.publish("Server/Status", "Online", qos=1, retain=True)

def on_disconnect(client, userdata, rc):
    if rc != 0:
        log("MQTT Unexpected disconnection.", "")

def on_message(client, userdata, message):
        #print("Received message '" + str(message.payload) + "' on topic '" + message.topic + "' with QoS " + str(message.qos))
    try:       
        topic = message.topic.split("/")
        typeofdata = topic[1]
        cursor = mysql.cursor()
              
        if(typeofdata == "Setup"):
            hostname = topic[0]
            query = ("SELECT * FROM computerdata WHERE hostname='"+hostname+"' LIMIT 1")
            cursor.execute(query)
            cursor.fetchall()

            if(cursor.rowcount == 0):
                log("Computer not found, adding as a new computer", "")
                add = ("INSERT INTO computerdata (hostname) VALUES ('"+hostname+"')")
                cursor.execute(add)
                ID = cursor.lastrowid
                mysql.commit()
                log("Added New Computer, ID:" + str(ID), "")
                mqtt.publish(hostname + "/Commands/ID", ID, qos=1, retain=False)
       
        if(typeofdata == "Status"):
            hostname = topic[0]
            online = "0"
            if(message.payload.decode("utf-8") == "Online"): online = "1"
            log("Setting computer: " + hostname + ", " + message.payload.decode("utf-8"), "")
            
            add = ("UPDATE computerdata SET online=%s, last_update=%s WHERE hostname=%s")
            x = datetime.datetime.now()
            last_update = x.strftime("%Y-%m-%d %H:%M:%S")
            data = (online, last_update, hostname)
            cursor.execute(add, data)
            mysql.commit()

        if(typeofdata == "Data"):
            ID = topic[0]
            title = topic[2]
            WMIName = ""

            x = datetime.datetime.now()
            last_update = x.strftime("%Y-%m-%d %H:%M:%S")

            if(title == "General"): WMIName = "WMI_ComputerSystem"
            if(title == "BIOS"): WMIName = "WMI_BIOS"
            if(title == "Startup"): WMIName = "WMI_Startup"
            if(title == "OptionalFeatures"): WMIName = "WMI_OptionalFeatures"
            if(title == "Processes"): WMIName = "WMI_Processes"
            if(title == "Services"): WMIName = "WMI_Services"
            if(title == "UserAccounts"): WMIName = "WMI_UserAccount"
            if(title == "VideoConfiguration"): WMIName = "WMI_VideoConfiguration"
            if(title == "LogicalDisk"): WMIName = "WMI_LogicalDisk"
            if(title == "PhysicalMemory"): WMIName = "WMI_PhysicalMemory"
            if(title == "PointingDevice"): WMIName = "WMI_PointingDevice"
            if(title == "Keyboard"): WMIName = "WMI_Keyboard"
            if(title == "BaseBoard"): WMIName = "WMI_BaseBoard"
            if(title == "DesktopMonitor"): WMIName = "WMI_DesktopMonitor"
            if(title == "Printer"): WMIName = "WMI_Printers"
            if(title == "PnPEntity"): WMIName = "WMI_PnPEntity"
            if(title == "SoundDevices"): WMIName = "WMI_SoundDevice"
            if(title == "SCSIController"): WMIName = "WMI_SCSIController"
            if(title == "Products"): WMIName = "WMI_Product"
            if(title == "NetworkAdapters"): WMIName = "WMI_NetworkAdapters"
            if(title == "Processor"): WMIName = "WMI_Processor"
            if(title == "Firewall"): WMIName = "WMI_Firewall"
            if(title == "PnPEntitys"): WMIName = "WMI_PnPEntity"
            if(title == "Battery"): WMIName = "WMI_Battery"
            if(title == "Filesystem"): WMIName = "WMI_Filesystem"

            if(title == "Screenshot"):
                log("Saving Screenshot", "")
                add = ("INSERT INTO screenshots (ComputerID, image) VALUES (%s, %s) ON DUPLICATE KEY UPDATE image=%s")
                data = (ID, message.payload, message.payload)
                cursor.execute(add, data)
                mysql.commit()
            if(title == "CMD"):
                hostname = topic[0]
                status = "Received"
                log("CMD Command Received for: " + hostname, "")
                add = ("UPDATE commands SET data_received=%s, time_received=%s, status=%s WHERE computerID=%s")
                data = (message.payload, last_update, status, hostname)
                cursor.execute(add, data)
                mysql.commit()
            if(title == "Heartbeat"):
                add = ("UPDATE computerdata SET heartbeat=%s, last_update=%s WHERE ID=%s")
                data = (last_update, last_update, ID)
                cursor.execute(add, data)
                mysql.commit()
            if(WMIName != ""):
                add = ("INSERT INTO wmidata (ComputerID, WMI_Name, WMI_Data) VALUES (%s, %s, %s)")
                data = (ID, WMIName, message.payload)
                cursor.execute(add, data)
                rowID = cursor.lastrowid
                add = ("UPDATE computerdata SET heartbeat=%s, last_update=%s WHERE ID=%s")
                data = (last_update, last_update, ID)
                cursor.execute(add, data)
                mysql.commit()

                log("Added " + WMIName + ", Row:" + str(rowID), "")

        cursor.close()
    except Exception as e:
        log("OnMQTTMessage Error", e)


def log(name, message):
    print(name)
    print(message)
    if(DEBUG):
        try:
            f = open(LOG_File, "a")
            f.write(str(name) + ": " + str(message) + "\n")
            f.close()
        except Exception as e:
            print("Error saving to log file")
            print(e)

log("Starting Setup", "")

try:
    mysql = mysql.connector.connect(user=MYSQL_Username, password=MYSQL_Password,host=MYSQL_Server, port=MYSQL_Port, database=MYSQL_Database)
except mysql.connector.Error as err:
    log("MySQL Error", err)

mqtt = mqtt.Client(client_id="Server1", clean_session=True)
mqtt.username_pw_set(MQTT_Username, MQTT_Password)
mqtt.will_set("Server/Status", "Offline", qos=1, retain=True)
mqtt.connect(MQTT_Server, port=MQTT_Port)
mqtt.on_message = on_message
mqtt.on_connect = on_connect
mqtt.on_disconnect = on_disconnect
mqtt.subscribe(MQTT_Topic, qos=1)
mqtt.loop_start()

count = 0
while True:
    time.sleep(1)
    count = count + 1