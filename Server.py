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
import rsa
from cryptography.fernet import Fernet
import crypto
import base64
import binascii
from Crypto import Random
from Crypto.Cipher import AES


# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32
BLOCK_SZ = 14

################################# SETUP ##################################
MQTT_Server = "****"
MQTT_Username = "******"
MQTT_Password = "*****"
MQTT_Port = 1884
MQTT_Topic = "#"

MYSQL_Server = "*****"
MYSQL_Username = "****"
MYSQL_Password = "*******"
MYSQL_Port = 3307
MYSQL_Database = "OpenRMM"

Server_Version = "1.4"
PHP_Encrption_Key = b'*******'

LOG_File = "C:\OpenRMMServer.log"
DEBUG = False

###########################################################################

required = {'paho-mqtt', 'mysql-connector-python', 'rsa', 'cryptography', 'pycryptodome'}
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
            Setup = {}
            topic = message.topic.split("/")
            typeofdata = topic[1]
            cursor = mysql.cursor()

            if(topic[0] == "OpenRMMServer"):
                if(typeofdata == "Command"):
                    Command(topic, message.payload)

            if(typeofdata == "Agent"):
                if(topic[2] == "New"):
                    hostname = topic[0]
                    # Generate Encrption Key Here, then encrypt all data with AES, send the encryption key encoded with public key given by server
                    log("Setup New Agent", "Computer not found, adding as a new computer")
                    add = ("INSERT INTO computers (hostname) VALUES ('" + hostname + "')")
                    cursor.execute(add)
                    ID = cursor.lastrowid
                    mysql.commit()
                    cursor.close()
                    
                    Setup["ID"] = str(ID)
                    Setup["Public_Key"] = Public_Key.save_pkcs1().decode('utf8')
                    Setup["Hostname"] = hostname

                    log("New Agent", "Added New Computer, ID:" + str(ID))
                    mqtt.publish(hostname + "/Commands/New", json.dumps(Setup), qos=1, retain=False)

                if(topic[2] == "Ready"):
                    ID = topic[0]
                    Setup["ID"] = str(ID)
                    Setup["Public_Key"] = Public_Key.save_pkcs1().decode('utf8')
                    log("Agent Ready", "Sending public key to agent: " + str(ID))
                    mqtt.publish(str(ID) + "/Commands/Ready", json.dumps(Setup), qos=1, retain=False)

                if(topic[2] == "Set"):
                    # When agent sends Startup, grab the encryption key & send the public key
                    ID = topic[0]
                    log("Set", "Recieved encryption salt from computer ID: " + str(ID) + ", sending Go command.")
                    Encrption_Keys[ID] = rsa.decrypt(message.payload, Private_Key).decode()
                    
                    add = ("UPDATE computers SET online=%s WHERE ID=%s")
                    data = ("1", ID)
                    cursor.execute(add, data)

                    mqtt.publish(str(ID) + "/Commands/Go", "true", qos=1, retain=False)

                    # Detect if the server is running an Agent, if so adjust for the front end
                    try:
                        if(exists("C:\OpenRMM.json")): # Agent Installed
                            f = open("C:\OpenRMM.json", "r")
                            Agent = json.loads(f.read())
                            if(Agent["Setup"]["ID"] == ID):
                                log("Agent", "Agent Detected, Computer ID: " + Agent["Setup"]["ID"])
                                add = ("UPDATE computers SET computer_type=%s WHERE ID=%s")
                                data = ("OpenRMM Server", Agent["Setup"]["ID"])
                                cursor.execute(add, data)
                                mysql.commit()
                    except Exception as e:
                      log("Agent", "Cannot determine if Agent is installed", "Warn")  
                
                if(topic[2] == "Sync" and topic[0] not in Encrption_Keys):
                    # Periodic sync of encryption keys
                    ID = topic[0]
                    log("Sync", "Recieved encryption salt from computer ID: " + str(ID))
                    Encrption_Keys[ID] = rsa.decrypt(message.payload, Private_Key).decode()
                        
            if(typeofdata == "Data"):
                ID = topic[0]
                title = topic[2]
                # Get the encrptyion Key
                if(ID in Encrption_Keys):
                    fernet = Fernet(Encrption_Keys[ID])
                    AllowedData = [
                        "General", "AgentLog",  "BIOS", "Startup", "OptionalFeatures", 
                        "Processes", "Services", "Users", "VideoConfiguration", "LogicalDisk", 
                        "MappedLogicalDisk", "PhysicalMemory", "PointingDevice", "Keyboard", 
                        "BaseBoard", "DesktopMonitor", "NetworkLoginProfile", "Printers", 
                        "PnPEntity", "SoundDevices", "SCSIController", "Products", 
                        "NetworkAdapters", "Processor", "Firewall", "PnPEntitys", "Battery", 
                        "Filesystem", "Agent", "OklaSpeedtest", "EventLog_System", "EventLog_Application",
                        "EventLog_Security", "EventLog_Setup", "Alert", "WindowsActivation"
                    ]

                    if(title == "AgentSettings"):
                        # Decrypt the payload
                        DecryptedData = fernet.decrypt(message.payload).decode()

                        log("Agent Settings", "Saving Settings for Computer ID " + str(ID))
                        add = ("UPDATE computers SET agent_settings=%s WHERE ID=%s")
                        data = (DecryptedData, ID)
                        cursor.execute(add, data)
                        mysql.commit()
                    if(title == "Screenshot"):
                        # Decrypt the payload
                        DecryptedData = fernet.decrypt(message.payload)

                        log("Screenshot", "Saving Screenshot for Computer ID " + str(ID))
                        add = ("INSERT INTO screenshots (computer_id, image) VALUES (%s, %s) ON DUPLICATE KEY UPDATE image=%s")
                        data = (ID, DecryptedData, DecryptedData)
                        cursor.execute(add, data)
                        mysql.commit()
                    if(title == "CMD"):
                        # Decrypt the payload
                        DecryptedData = fernet.decrypt(message.payload).decode()

                        log("CMD", "Command Received for: " + ID)
                        add = ("UPDATE commands SET data_received=%s, time_received=NOW(), status=%s WHERE computer_id=%s")
                        data = (DecryptedData, "Received", ID)
                        cursor.execute(add, data)
                        mysql.commit()
                    if(title == "Heartbeat"):
                        cursor.execute("UPDATE computers SET last_update=NOW() WHERE ID=" + ID)
                        mysql.commit()
                    if(title in AllowedData):
                        # Decrypt the payload
                        DecryptedData = fernet.decrypt(message.payload).decode()
                        # Encrypt for PHP
                        EncryptedData = encrypt(DecryptedData)

                        add = ("INSERT INTO computer_data (computer_id, name, data) VALUES (%s, %s, %s)")
                        data = (ID, title, EncryptedData)
                        cursor.execute(add, data)
                        rowID = cursor.lastrowid
                        mysql.commit()

                        log("Data", "Inserted " + title + " for computer ID: " + str(ID) + ", Row: " + str(rowID))
                elif(title == "Heartbeat"): # Update missing keys when agent sends heartbeat
                    # Encryption key not found for this agent, asking for key
                    Setup["ID"] = str(ID)
                    Setup["Public_Key"] = Public_Key.save_pkcs1().decode('utf8')
                    mqtt.publish(str(ID) + "/Commands/Sync", json.dumps(Setup), qos=1, retain=False)
                else:
                    print("Error - Title: Encription, Message: No Encription key found for agent ID: " + str(ID))
            cursor.close()
        else:
            mysql.reconnect(attempts=10, delay=0)
    except Exception as e:
        print(traceback.format_exc())
        log("OnMQTTMessage", e, "Error")

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

def encrypt(data: dict) -> str:
    global PHP_Encrption_Key
    data_json_64 = base64.b64encode(json.dumps(data).encode('ascii'))
    try:
        key = binascii.unhexlify(PHP_Encrption_Key)
        iv = Random.get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_GCM, iv)
        encrypted, tag = cipher.encrypt_and_digest(data_json_64)
        encrypted_64 = base64.b64encode(encrypted).decode('ascii')
        iv_64 = base64.b64encode(iv).decode('ascii')
        tag_64 = base64.b64encode(tag).decode('ascii')
      
        return encrypted_64
    except Exception as e:
        print(traceback.format_exc())
        return ''

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
Encrption_Keys = {}
Salt_Keys = {}
log("Setup", "Gernerating RSA Keys")
Public_Key, Private_Key = rsa.newkeys(2048)
log("Setup", "Starting OpenRMM Server Setup, Version: " + Server_Version)

try:
    mysql = mysql.connector.connect(user=MYSQL_Username, password=MYSQL_Password,host=MYSQL_Server, port=MYSQL_Port, database=MYSQL_Database)
    if (mysql):
        log("MySQL", "Connection Successfull")
        # Update Server Status
        cursor = mysql.cursor()
        update = ("UPDATE general SET server_status=%s WHERE ID=%s")
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

#threadDBCleanup = threading.Thread(target=DBCleanup, args=[60]) # Run every x minutes
#threadDBCleanup.start()

while True: time.sleep(0.1)