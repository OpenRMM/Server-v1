#!/usr/bin/env python3


#To DO:
# Send session id on sync
# Create Changelog

import os, sys
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
import Crypto
import base64
import binascii
from Crypto import Random
from Crypto.Cipher import AES
from dictdiffer import diff, patch, swap, revert
import servicemanager
import win32serviceutil, win32event, win32service, win32con, win32evtlogutil, win32evtlog, win32security, win32api, winerror


# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32
BLOCK_SZ = 14

################################# SETUP ##################################
MQTT_Server = "*******"
MQTT_Username = "*******"
MQTT_Password = "****"
MQTT_Port = 1884
MQTT_Topic = "#"

MYSQL_Server = "****"
MYSQL_Username = "****"
MYSQL_Password = "******"
MYSQL_Port = 3307
MYSQL_Database = "OpenRMM"

Service_Name = "OpenRMMServer"
Service_Display_Name = "OpenRMM Server"
Service_Description = "A free open-source remote monitoring & management tool."

Server_Version = "1.6"
PHP_Encryption_Key = b'******'

LOG_File = "C:\OpenRMMServer.log"
DEBUG = False

###########################################################################

required = {'paho-mqtt', 'mysql-connector-python', 'rsa', 'cryptography', 'pycryptodome', 'dictdiffer'}
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


class OpenRMMServer(win32serviceutil.ServiceFramework):
    _svc_name_ = Service_Name
    _svc_display_name_ = Service_Display_Name
    _svc_description_ = Service_Description
    _svc_interactive_process_ = True
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.isrunning = False

    def SvcDoRun(self):
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

        self.AgentLog = []
        self.Encryption_Keys = {}
        self.Session_IDs = {}
        self.Cache = {}
        self.isrunning = True
        self.log("Setup", "Generating RSA Keys")
        self.Public_Key, self.Private_Key = rsa.newkeys(2048)
        self.log("Setup", "Starting OpenRMM Server Setup, Version: " + Server_Version)

        try:
            self.mysql = mysql.connector.connect(user=MYSQL_Username, password=MYSQL_Password,host=MYSQL_Server, port=MYSQL_Port, database=MYSQL_Database)
            if (self.mysql):
                self.log("MySQL", "Connection Successfull")
                # Update Server Status
                cursor = self.mysql.cursor()
                update = ("UPDATE general SET server_status=%s WHERE ID=%s")
                data = ("1", 1)
                cursor.execute(update, data)
                self.mysql.commit()
                cursor.close()
            else:
                self.log("MySQL Error", "Cannot Connect to MySQL")
        except self.mysql.connector.Error as err:
            if(DEBUG): print(traceback.format_exc())
            self.log("MySQL", err, "Error")

        self.log("MQTT", "Connecting to MQTT")
        client_id = os.environ['COMPUTERNAME'] + str(randint(1000, 10000))
        self.mqtt = mqtt.Client(client_id=client_id, clean_session=True)
        self.mqtt.username_pw_set(MQTT_Username, MQTT_Password)
        self.mqtt.will_set("OpenRMMServer/Status", "Offline", qos=1, retain=True)
        self.mqtt.connect(MQTT_Server, port=MQTT_Port)
        self.mqtt.on_message = self.on_message
        self.mqtt.on_connect = self.on_connect
        self.mqtt.on_disconnect = self.on_disconnect
        self.mqtt.subscribe(MQTT_Topic, qos=1)
        self.mqtt.loop_start()

        while self.isrunning: time.sleep(0.1)

    def SvcStop(self):
        self.isrunning = False
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)  

    # The callback for when the client receives a CONNACK response from the server.
    def on_connect(self, client, userdata, flags, rc):
        self.log("MQTT", "Connected to server: " + MQTT_Server + " with result code: " + str(rc))
        if (rc==0):
            self.mqtt.publish("OpenRMMServer/Status", "Online", qos=1, retain=True)

    def on_disconnect(self, client, userdata, rc):
        if rc != 0:
            self.log("MQTT", "Unexpected disconnection.", "Warn")
            # Update Server Status
            cursor = self.mysql.cursor()
            update = ("UPDATE general SET server_status=%s WHERE ID=%s")
            data = ("0", 1)
            cursor.execute(update, data)
            self.mysql.commit()

    def on_message(self, client, userdata, message):
        #print("Received message '" + str(message.payload) + "' on topic '" + message.topic + "' with QoS " + str(message.qos))
        try:
            if (self.mysql.is_connected()):
                Setup = {}
                topic = message.topic.split("/")
                typeofdata = topic[1]
                cursor = self.mysql.cursor()

                if(topic[0] == "OpenRMMServer"):
                    if(typeofdata == "Command"):
                        self.Command(topic, message.payload)

                if(typeofdata == "Agent"):
                    if(topic[2] == "New"):
                        hostname = topic[0]
                        # Generate Encryption Key Here, then encrypt all data with AES, send the encryption key encoded with public key given by server
                        self.log("Setup New Agent", "Computer not found, adding as a new computer")
                        add = ("INSERT INTO computers () VALUES ()")
                        cursor.execute(add)
                        ID = cursor.lastrowid
                        self.mysql.commit()
                        cursor.close()
                        
                        Setup["ID"] = str(ID)
                        Setup["Public_Key"] = self.Public_Key.save_pkcs1().decode('utf8')
                        Setup["Hostname"] = hostname

                        self.log("New Agent", "Added New Computer, ID:" + str(ID))
                        self.mqtt.publish(hostname + "/Commands/New", json.dumps(Setup), qos=1, retain=False)

                    if(topic[2] == "Ready"):
                        ID = topic[0]
                        payload = json.loads(message.payload)

                        # Set session ID, this will be used later for online/offline
                        self.Session_IDs[payload['Session_ID']] = ID

                        Setup["ID"] = str(ID)
                        Setup["Public_Key"] = self.Public_Key.save_pkcs1().decode('utf8')
                        self.log("Agent Ready", "Sending public key to agent: " + str(ID))
                        self.mqtt.publish(str(ID) + "/Commands/Ready", json.dumps(Setup), qos=1, retain=False)

                    if(topic[2] == "Set"):
                        # When agent sends Startup, grab the encryption key & send the public key
                        ID = topic[0]
                        self.log("Set", "Recieved encryption key, session ID from agent ID: " + str(ID) + ", sending Go command.")
                        self.Encryption_Keys[ID] = rsa.decrypt(message.payload, self.Private_Key).decode()
                        self.mqtt.publish(str(ID) + "/Commands/Go", "true", qos=1, retain=False)

                        # Detect if the server is running an Agent, if so adjust for the front end
                        try:
                            if(exists("C:\OpenRMM.json")): # Agent Installed
                                f = open("C:\OpenRMM.json", "r")
                                Agent = json.loads(f.read())
                                if(Agent["Setup"]["ID"] == ID):
                                    self.log("Agent", "Agent Detected, Computer ID: " + Agent["Setup"]["ID"])
                                    add = ("UPDATE computers SET computer_type=%s WHERE ID=%s")
                                    data = ("OpenRMM Server", Agent["Setup"]["ID"])
                                    cursor.execute(add, data)
                                    self.mysql.commit()
                        except Exception as e:
                            self.log("Agent", "Cannot determine if Agent is installed", "Warn")  
                    
                    if(topic[2] == "Sync" and topic[0] not in self.Encryption_Keys):
                        # Periodic sync of encryption keys
                        ID = topic[0]
                        self.log("Sync", "Recieved encryption key from agent ID: " + str(ID))
                        self.Encryption_Keys[ID] = rsa.decrypt(message.payload, self.Private_Key).decode()

                if(typeofdata == "Status"):
                    # Get ID from session ID, recieved earlier
                    session_id = topic[0]
                    if(session_id in self.Session_IDs):
                        ID = self.Session_IDs[session_id]
                        self.log("Agent", "Changing Online/Offline status for agent ID: " + ID)
                        add = ("UPDATE computers SET online=%s WHERE ID=%s")
                        data = (int(message.payload), ID)
                        cursor.execute(add, data)
                        self.mysql.commit()

                if(typeofdata == "Data"):
                    ID = topic[0]
                    title = topic[2]
                    # Get the encrptyion Key
                    if(ID in self.Encryption_Keys):
                        fernet = Fernet(self.Encryption_Keys[ID])
                        AllowedData = [
                            "general", "agent_log",  "bios", "startup", "optional_features", 
                            "processes", "services", "users", "video_configuration", "logical_disk", 
                            "mapped_logical_disk", "physical_memory", "pointing_device", "keyboard", 
                            "base_board", "desktop_monitor", "network_login_profile", "printers", 
                            "sound_devices", "scsi_controller", "products", "network_adapters", "processor",
                            "firewall", "pnp_entities", "battery", "filesystem", "agent", "okla_speedtest",
                            "event_log_system", "event_log_application","event_log_security", "event_log_setup",
                            "alert", "windows_activation", "agent_settings", "serial_ports"
                        ]

                        if(title == "CMD"):
                            # Decrypt the payload
                            DecryptedData = json.loads(fernet.decrypt(message.payload).decode())
                            # Encrypt for PHP
                            EncryptedData = self.encrypt(DecryptedData['Response'])
                            
                            commandID = DecryptedData['Request']['commandID']
                            self.log("CMD", "Command Received for: " + ID)
                            add = ("UPDATE commands SET data_received=%s, time_received=NOW(), status=%s WHERE computer_id=%s AND ID=%s")
                            data = (EncryptedData, "Received", ID, commandID)
                            cursor.execute(add, data)
                            self.mysql.commit()

                        elif(title[0:11] == "screenshot_"):
                            # Decrypt the payload
                            DecryptedData = fernet.decrypt(message.payload)

                            # Update Or Insert computer_data
                            query = ("UPDATE computer_data set data=%s WHERE computer_id=%s AND name=%s LIMIT 1")
                            cursor.execute(query, (DecryptedData, ID, title))
                            
                            if(cursor.rowcount == 0):
                                query = ("INSERT INTO computer_data (computer_id, name, data) VALUES (%s, %s, %s)")
                                cursor.execute(query, (ID, title, DecryptedData))
                                self.log("Data", "Inserted " + title + " for agent ID: " + str(ID) + ", Row: " + str(cursor.lastrowid))
                            else:
                                self.log("Data", "Updated " + title + " for agent ID: " + str(ID))
                            self.mysql.commit()

                        elif(title in AllowedData):
                            loadType = topic[3]
                            # Decrypt the payload
                            DecryptedData = json.loads(fernet.decrypt(message.payload).decode())
                            cacheName = ID + "-" + title

                            if(loadType == "Update"):
                                if(cacheName not in self.Cache):
                                    self.Cache[cacheName] = {}
                                    # Cannot find existing data in Cache, So get data from SQL
                                    query = "SELECT data FROM computer_data WHERE computer_id=%s AND name=%s ORDER BY ID DESC LIMIT 1"
                                    cursor.execute(query, (ID, title))
                                    for data in cursor:
                                        self.Cache[cacheName] = json.loads(self.decrypt(data[0].decode("UTF-8")))["Response"]
                                        
                                if(cacheName in self.Cache):
                                    # Process data and update array, update full array to DB
                                    getDiff = DecryptedData['Response']
                                    result = (y for y in getDiff)
                                    self.Cache[cacheName] = patch(result, self.Cache[cacheName])

                                    # Encrypt for PHP
                                    data = {"Request": DecryptedData['Request'], "Response": self.Cache[cacheName]}
                                    EncryptedData = self.encrypt(json.dumps(data))

                                    # Update Or Insert computer_data
                                    query = ("UPDATE computer_data set data=%s WHERE computer_id=%s AND name=%s LIMIT 1")
                                    cursor.execute(query, (EncryptedData, ID, title))

                                    if(cursor.rowcount == 0):
                                        query = ("INSERT INTO computer_data (computer_id, name, data) VALUES (%s, %s, %s)")
                                        cursor.execute(query, (ID, title, EncryptedData))
                                        self.log("Data", "Inserted " + title + " for agent ID: " + str(ID) + ", Row: " + str(cursor.lastrowid))
                                    else:
                                        self.log("Data", "Updated " + title + " for agent ID: " + str(ID))

                                    # Proccess Changelog
                                    try:
                                        if(title != "filesystem" and title != "agent_log"):
                                            for (diff) in getDiff:
                                                if(diff[0] == "change"):
                                                    query = ("INSERT INTO changelog (computer_id, computer_data_name, computer_data_key, old_value, new_value, change_type) VALUES (%s, %s, %s,%s, %s, %s)")
                                                    if(type(diff[1]) == list):  # Convert list of numbers to . delimited string, similar to php implode
                                                        string_ints = [str(int) for int in diff[1]]
                                                        diff[1] = ".".join(string_ints)
                                                    cursor.execute(query, (ID, title, diff[1], str(diff[2][0]), str(diff[2][1]), diff[0]))
                                                elif(diff[0] == "add"):
                                                    query = ("INSERT INTO changelog (computer_id, computer_data_name, computer_data_key, old_value, new_value, change_type) VALUES (%s, %s, %s,%s, %s, %s)")
                                                    for (subdiff) in diff[2]:
                                                        cursor.execute(query, (ID, title, (str(diff[1]) + "." + str(subdiff[0])), "", str(subdiff[1]), "add"))
                                    except Exception as e:
                                        exception_type, exception_object, exception_traceback = sys.exc_info()
                                        line_number = exception_traceback.tb_lineno
                                        if(DEBUG): print(traceback.format_exc())
                                        self.log("OnMQTTMessage - "+ str(line_number), e, "Error")

                                    self.mysql.commit()
                                else:
                                    return

                    elif(title == "heartbeat"): # Update missing keys when agent sends heartbeat
                        # Encryption key not found for this agent, asking for key
                        Setup["ID"] = str(ID)
                        Setup["Public_Key"] = self.Public_Key.save_pkcs1().decode('utf8')
                        self.mqtt.publish(str(ID) + "/Commands/Sync", json.dumps(Setup), qos=1, retain=False)
                    else:
                        print("Error - Title: Encryption, Message: No Encryption key found for agent ID: " + str(ID))
                cursor.close()
            else:
                self.mysql.reconnect(attempts=100, delay=10) # Retry up to 16 min.
        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            line_number = exception_traceback.tb_lineno
            if(DEBUG): print(traceback.format_exc())
            self.log("OnMQTTMessage - "+ str(line_number), e, "Error")

    # Supported Commands: Service/Stop
    def Command(self, topic, command = ""):
        try:
            self.log("Commands", "Proccessing Command: " + command)
            if("Service" in topic):
                if(topic[3] == "Stop"): 
                    self.log("Commands", "Recieved service stop command from MQTT")
                    self.SvcStop()
            #if("getAgentLog" in topic):
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Commands", e, "Error")

    # Log, Type: Info, Warn, Error
    def log(self, title, message, errorType="Info"):
        print(errorType + " - " + "Title: " + title + ", Message: " + str(message))
        try:
            logEvent = {}
            logEvent["Title"] = title 
            logEvent["Message"] = str(message)
            logEvent["Type"] = errorType
            logEvent["Time"] = str(datetime.datetime.now())
            self.AgentLog.append(logEvent)
            
            f = open(LOG_File, "a")
            f.write(str(datetime.datetime.now()) + " " + errorType + " - " + "Title: " + title + ", Message: " + str(message) + "\n")
            f.close()
        except Exception as e:
            print("Error saving to log file")
            print(e)
            if(DEBUG): print(traceback.format_exc())

    # https://gist.github.com/ahbanavi/ff3c0711b45f5056f821c00438af8f67
    def encrypt(self, data: dict) -> str:
        global PHP_Encryption_Key
        data_json_64 = base64.b64encode(json.dumps(data).encode('ascii'))
        try:
            key = binascii.unhexlify(PHP_Encryption_Key)
            iv = Random.get_random_bytes(AES.block_size)
            cipher = AES.new(key, AES.MODE_GCM, iv)
            encrypted, tag = cipher.encrypt_and_digest(data_json_64)
            encrypted_64 = base64.b64encode(encrypted).decode('ascii')
            iv_64 = base64.b64encode(iv).decode('ascii')
            tag_64 = base64.b64encode(tag).decode('ascii')
            json_data = {'iv': iv_64, 'data': encrypted_64, 'tag': tag_64}
            return base64.b64encode(json.dumps(json_data).encode('ascii')).decode('ascii')
        except:  # noqa
            return ''
        
    def decrypt(self, data: str) -> dict:
        global PHP_Encryption_Key
        try:
            key = binascii.unhexlify(PHP_Encryption_Key)
            encrypted = json.loads(base64.b64decode(str(data)).decode('ascii'))
            encrypted_data = base64.b64decode(encrypted['data'])
            iv = base64.b64decode(encrypted['iv'])
            tag = base64.b64decode(encrypted['tag'])
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt_and_verify(encrypted_data, tag)
            return json.loads(base64.b64decode(decrypted).decode('ascii'))
        except Exception as e:
            print(traceback.format_exc())
            return ["Error"]

        
if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(OpenRMMServer)