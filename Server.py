#!/usr/bin/env python3

import os
from os.path import exists
import paho.mqtt.client as mqtt
import json
import time
import subprocess
import threading
import mysql.connector
import datetime
from mysql.connector.locales.eng import client_error
from random import randint
import pkg_resources
import traceback

################################# SETUP ##################################
MQTT_Server = "*****"
MQTT_Username = "*****"
MQTT_Password = "*****"
MQTT_Port = 1884
MQTT_Topic = "#"

MYSQL_Server = "*****"
MYSQL_Username = "*****"
MYSQL_Password = "*****"
MYSQL_Port = 3307
MYSQL_Database = "rmm"

Server_Version = "1.3"

LOG_File = "C:\OpenRMMServer.log"
DEBUG = False

###########################################################################

required = {'paho-mqtt', 'mysql-connector-python'}
installed = {pkg.key for pkg in pkg_resources.working_set}
missing = required - installed

if(len(missing) > 0):
    print("Missing Modules, please install with the command: python -m pip install modulename")
    print(missing)
    print("Attempting to install modules")
    python = sys.executable
    subprocess.check_call([python, '-m', 'pip', 'install', *missing], stdout=subprocess.DEVNULL)
    print("Please restart service and try again.")
    sys.exit()

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    log("MQTT", "Connected to server: " + MQTT_Server + " with result code: " + str(rc))
    if (rc==0):
        mqtt.publish("OpenRMMServer/Status", "Online", qos=1, retain=True)

def on_disconnect(client, userdata, rc):
    if rc != 0:
        log("MQTT", "Unexpected disconnection.", "Warn")
        # Update Server Status
        cursor = mysql.cursor()
        update = ("UPDATE general SET serverStatus=%s WHERE ID=%s")
        data = ("0", 1)
        cursor.execute(update, data)
        mysql.commit()

def on_message(client, userdata, message):
    #print("Received message '" + str(message.payload) + "' on topic '" + message.topic + "' with QoS " + str(message.qos))
    try:
        if (mysql.is_connected()):

            topic = message.topic.split("/")
            typeofdata = topic[1]
            cursor = mysql.cursor()

            if(topic[0] == "OpenRMMServer"):
                if(typeofdata == "Command"):
                    Command(topic, message.payload)

            if(typeofdata == "Setup"):
                hostname = topic[0]
                query = ("SELECT * FROM computerdata WHERE hostname='" + hostname + "' LIMIT 1")
                cursor.execute(query)
                cursor.fetchall()

                if(cursor.rowcount == 0):
                    log("Computer not found, adding as a new computer", "")
                    add = ("INSERT INTO computerdata (hostname) VALUES ('" + hostname + "')")
                    cursor.execute(add)
                    ID = cursor.lastrowid
                    mysql.commit()
                    cursor.close()
                    log("Agent Setup", "Added New Computer, ID:" + str(ID))
                    mqtt.publish(hostname + "/Commands/ID", ID, qos=1, retain=False)
        
            if(typeofdata == "Status"):
                ID = topic[0]
                online = "0"
                if(message.payload.decode("utf-8") == "Online"): online = "1"
                log("Agent Status", "Setting computer: " + ID + ", " + message.payload.decode("utf-8"))
                
                add = ("UPDATE computerdata SET online=%s WHERE ID=%s")
                data = (online, ID)
                cursor.execute(add, data)

                # Detect if the server is running an Agent, if so adjust for the front end
                try:
                    if(exists("C:\OpenRMM.json")): # Agent Installed
                        f = open("C:\OpenRMM.json", "r")
                        Agent = json.loads(f.read())
                        if(Agent["ID"] == ID):
                            log("Agent", "Agent Detected, Computer ID: " + Agent["ID"])
                            add = ("UPDATE computerdata SET computer_type=%s WHERE ID=%s")
                            data = ("OpenRMM Server", Agent["ID"])
                            cursor.execute(add, data)
                            mysql.commit()
                except Exception as e:
                   log("Agent", "Cannot determine if Agent is installed", "Warn")              
            
            if(typeofdata == "Data"):
                ID = topic[0]
                title = topic[2]

                AllowedData = [
                    "General", "AgentLog",  "BIOS", "Startup", "OptionalFeatures", 
                    "Processes", "Services", "Users", "VideoConfiguration", "LogicalDisk", 
                    "MappedLogicalDisk", "PhysicalMemory", "PointingDevice", "Keyboard", 
                    "BaseBoard", "DesktopMonitor", "NetworkLoginProfile", "Printer", 
                    "PnPEntity", "SoundDevices", "SCSIController", "Products", 
                    "NetworkAdapters", "Processor", "Firewall", "PnPEntitys", "Battery", 
                    "Filesystem", "Agent", "OklaSpeedtest", "EventLog_System", "EventLog_Application",
                    "EventLog_Security", "EventLog_Setup", "Alert", "WindowsActivation"
                ]

                if(title == "AgentSettings"):
                    log("Agent Settings", "Saving Settings for Computer ID " + str(ID))
                    add = ("UPDATE computerdata SET agent_settings=%s WHERE ID=%s")
                    data = (message.payload, ID)
                    cursor.execute(add, data)
                    mysql.commit()
                if(title == "Screenshot"):
                    log("Screenshot", "Saving Screenshot for Computer ID " + str(ID))
                    add = ("INSERT INTO screenshots (ComputerID, image) VALUES (%s, %s) ON DUPLICATE KEY UPDATE image=%s")
                    data = (ID, message.payload, message.payload)
                    cursor.execute(add, data)
                    mysql.commit()
                if(title == "CMD"): 
                    log("CMD", "Command Received for: " + ID)
                    add = ("UPDATE commands SET data_received=%s, time_received=NOW(), status=%s WHERE computerID=%s")
                    data = (message.payload, "Received", ID)
                    cursor.execute(add, data)
                    mysql.commit()
                if(title == "Heartbeat"):
                    add = ("UPDATE computerdata SET last_update=NOW() WHERE ID=%s")
                    cursor.execute(add, (ID))
                    mysql.commit()
                if(title in AllowedData):
                    add = ("INSERT INTO wmidata (ComputerID, WMI_Name, WMI_Data) VALUES (%s, %s, %s)")
                    data = (ID, title, message.payload)
                    cursor.execute(add, data)
                    rowID = cursor.lastrowid
                    mysql.commit()

                    log("WMIData", "Inserted " + title + " for computer ID: " + str(ID) + ", Row: " + str(rowID))
            cursor.close()
        else:
            mysql.reconnect(attempts=10, delay=0)
    except Exception as e:
        log("OnMQTTMessage", e, "Error")

# Log, Type: Info, Warn, Error
def log(title, message, errorType="Info"):
    print(errorType + " - " + "Title: " + title + ", Message: " + str(message))
    try:
        logEvent = {}
        logEvent["Title"] = title 
        logEvent["Message"] = str(message)
        logEvent["Type"] = errorType
        logEvent["Time"] = str(datetime.datetime.now())
        AgentLog.append(logEvent)
        
        f = open(LOG_File, "a")
        f.write(str(datetime.datetime.now()) + " " + errorType + " - " + "Title: " + title + ", Message: " + str(message) + "\n")
        f.close()
    except Exception as e:
        print("Error saving to log file")
        print(e)
        if(DEBUG): print(traceback.format_exc())
        
def DBCleanup(minutes=60):
    time.sleep(5)
    try:
        loopCount = 0
        while True:
            if (mysql):
                loopCount = loopCount +1
                time.sleep(1)
                if(loopCount == (60 * minutes)):
                    loopCount = 0
                    log("Database Cleanup", "Starting DB Cleanup")

    except Exception as e:
        if(DEBUG): print(traceback.format_exc())
        log("Database Cleanup", e, "Error")

# Supported Commands: Service/Stop
def Command(topic, command = ""):
    try:
        log("Commands", "Proccessing Command: " + command)
        if("Service" in topic):
            if(topic[3] == "Stop"): 
                log("Commands", "Recieved service stop command from MQTT")
                sys.stop()
        #if("getAgentLog" in topic):


    except Exception as e:
        if(DEBUG): print(traceback.format_exc())
        log("Commands", e, "Error")

print("   ____                   _____  __  __ __  __ ")
print("  / __ \                 |  __ \|  \/  |  \/  |")
print(" | |  | |_ __   ___ _ __ | |__) | \  / | \  / |")
print(" | |  | | '_ \ / _ \ '_ \|  _  /| |\/| | |\/| |")
print(" | |__| | |_) |  __/ | | | | \ \| |  | | |  | |")
print("  \____/| .__/ \___|_| |_|_|  \_\_|  |_|_|  |_|")
print("        | |                                    ")
print("        |_|                                    ")
print("Github: https://github.com/OpenRMM/")
print("Created By: Brad & Brandon Sanders")
print("")

AgentLog = []
log("Setup", "Starting OpenRMM Server Setup, Version: " + Server_Version)

try:
    mysql = mysql.connector.connect(user=MYSQL_Username, password=MYSQL_Password,host=MYSQL_Server, port=MYSQL_Port, database=MYSQL_Database)
    if (mysql):
        log("MySQL", "Connection Successfull")
        # Update Server Status
        cursor = mysql.cursor()
        update = ("UPDATE general SET serverStatus=%s WHERE ID=%s")
        data = ("1", 1)
        cursor.execute(update, data)
        mysql.commit()
        cursor.close()
    else:
        log("MySQL Error", "Cannot Connect to MySQL")
except mysql.connector.Error as err:
    if(DEBUG): print(traceback.format_exc())
    log("MySQL", err, "Error")

client_id = os.environ['COMPUTERNAME'] + str(randint(1000, 10000))
mqtt = mqtt.Client(client_id=client_id, clean_session=True)
mqtt.username_pw_set(MQTT_Username, MQTT_Password)
mqtt.will_set("OpenRMMServer/Status", "Offline", qos=1, retain=True)
mqtt.connect(MQTT_Server, port=MQTT_Port)
mqtt.on_message = on_message
mqtt.on_connect = on_connect
mqtt.on_disconnect = on_disconnect
mqtt.subscribe(MQTT_Topic, qos=1)
mqtt.loop_start()

log("Setup", "Starting DB Cleanup thread")
time.sleep(1)
threadDBCleanup = threading.Thread(target=DBCleanup, args=[60]) # Run every x minutes
threadDBCleanup.start()

while True: time.sleep(0.1)