#!/usr/bin/env python3

#To DO:
# Send session id on sync
# Create Changelog

import os, sys
from os.path import exists
import paho.mqtt.client as mqtt
import json
import time
import datetime
import subprocess
import threading
import pymysql.cursors
from random import randint
import pkg_resources
import traceback
import rsa
from cryptography.fernet import Fernet
import base64
import binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from dictdiffer import diff, patch, swap, revert
import win32serviceutil, win32event, win32service, win32con, win32evtlogutil, win32evtlog, win32security, win32api, winerror
import psutil
import platform
import socket

# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32
BLOCK_SZ = 14

################################# SETUP ##################################
print("dasfasdfasfasdf")
try:
    if(exists("C:\OpenRMM\Server\OpenRMM.json")):
        file = open("C:\OpenRMM\Server\OpenRMM.json", "r").read()
        server_settings = json.loads(file)
    else:
        print("Read config file, could not get data from file: C:\OpenRMM\Server\OpenRMM.json, file dont exist")
except Exception as e:
    print("Read config file error: ")
    print(e)
    sys.exit()

###########################################################################

required = {'paho-mqtt', 'pymysql', 'rsa', 'cryptography', 'pycryptodome', 'dictdiffer', 'psutil'}
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
    _svc_name_ = server_settings["Service"]["name"]
    _svc_display_name_ = server_settings["Service"]["display_name"]
    _svc_description_ = server_settings["Service"]["description"]
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
        print("Created By: Brad & Brandon Sanders, 2021-2022")
        print("")

        self.isrunning = True
        self.log("Setup", "Generating RSA Keys")
        self.Public_Key, self.Private_Key = rsa.newkeys(2048)

        self.log("Setup", "Starting OpenRMM Server Setup, Version: " + server_settings["Server"]["version"])

        self.thread_stats = threading.Thread(target=self.stats, args=[True]).start()

        self.log("MQTT", "Connecting to MQTT")
        client_id = os.environ['COMPUTERNAME'] + "_" + str(randint(1000, 10000))
        self.mqtt = mqtt.Client(client_id=client_id, clean_session=True)
        self.mqtt.username_pw_set(server_settings["MQTT"]["username"], server_settings["MQTT"]["password"])
        self.mqtt.connect(server_settings["MQTT"]["host"], port=server_settings["MQTT"]["port"])
        self.mqtt.on_message = self.on_message
        self.mqtt.on_connect = self.on_connect
        self.mqtt.on_disconnect = self.on_disconnect
        self.mqtt.subscribe(server_settings["MQTT"]["topic"], qos=1)
        self.mqtt.loop_start()
   
        while self.isrunning: time.sleep(0.5)

    # Service stop request
    def SvcStop(self):
        print("Stopping service.")
        server_settings = None
        self.isrunning = False
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)  

    # Commands: shutdown, restart, stop service, restart service
    def Commands(self, command):
        self.log("Commands", "Running command: " + str(command))
        if command == 'stop service':
            win32serviceutil.StopService(server_settings["Service"]["name"])
        elif command == 'restart service':
            os.execv(sys.argv[0], sys.argv)
        elif command == 'shutdown':
            data = str(subprocess.check_output("shutdown /s /f /t 60", shell=True), "utf-8")
            data = None
        elif command == 'restart':
            data = str(subprocess.check_output("shutdown /r /f /t 30", shell=True), "utf-8")
            data = None

    # The callback for when the client receives a CONNACK response from the server.
    def on_connect(self, client, userdata, flags, rc):
        self.log("MQTT", "Connected to server: " + server_settings["MQTT"]["host"] + " with result code: " + str(rc))

    def on_disconnect(self, client, userdata, rc):
        self.log("MQTT", "Unexpected disconnection.", "Warn")

    def on_message(self, client, userdata, message):
        try:
            #print("MQTT: Received message '" + str(message.payload) + "' on topic '" + message.topic + "' with QoS " + str(message.qos))
            self.mysql = pymysql.connect(user=server_settings["MySQL"]["username"], password=server_settings["MySQL"]["password"], host=server_settings["MySQL"]["host"], port=server_settings["MySQL"]["port"], database=server_settings["MySQL"]["database"], cursorclass=pymysql.cursors.DictCursor)
            with self.mysql:
                with self.mysql.cursor() as cursor:
                    Setup = {}
                    topic = message.topic.split("/")
                    typeofdata = topic[1]

                    if(typeofdata == "Server"): # 1\Server\Command->payload: shutdown
                        ID = topic[0]
                        if("ID" in server_settings["Server"]["dbinfo"]):
                            if(server_settings["Server"]["dbinfo"]["ID"] == int(ID)):
                                if(topic[2] == "Command"): # shutdown, restart, stop service, restart service
                                    command = json.loads(message.payload)
                                    self.Commands(command["payload"])
                                
                    elif(typeofdata == "Agent"):
                        if(topic[2] == "New"):
                            hostname = topic[0]
                            # Generate Encryption Key Here, then encrypt all data with AES, send the encryption key encoded with public key given by server
                            self.log("Setup New Agent", "Computer not found, adding as a new computer")
                            add = ("INSERT INTO computers () VALUES()")
                            self.cursor.execute(add)
                            ID = cursor.lastrowid
                            self.mysql.commit()
                            
                            Setup["ID"] = str(ID)
                            Setup["Public_Key"] = self.Public_Key.save_pkcs1().decode('utf8')
                            Setup["Hostname"] = hostname

                            self.log("New Agent", "Added New Computer, ID:" + str(ID))
                            self.mqtt.publish(hostname + "/Commands/New", json.dumps(Setup), qos=1, retain=False)

                        if(topic[2] == "Ready"):
                            ID = topic[0]
                            payload = json.loads(message.payload)

                            # Set session ID, this will be used later for online/offline
                            server_settings["Session ID"][payload['Session_ID']] = ID
                            
                            Setup["ID"] = str(ID)
                            Setup["Public_Key"] = self.Public_Key.save_pkcs1().decode('utf8')
                            self.log("Agent Ready", "Sending public key to agent: " + str(ID))
                            self.mqtt.publish(str(ID) + "/Commands/Ready", json.dumps(Setup), qos=1, retain=False)

                        if(topic[2] == "Set"):
                            # When agent sends Startup, grab the encryption key & send the public key
                            ID = topic[0]
                            self.log("Set", "Recieved encryption key, session ID from agent ID: " + str(ID) + ", sending Go command.")
                            server_settings["Encryption Keys"][ID] = rsa.decrypt(message.payload, self.Private_Key).decode()
                            self.mqtt.publish(str(ID) + "/Commands/Go", "true", qos=1, retain=False)
                        
                        if(topic[2] == "Sync" and topic[0] not in server_settings["Encryption Keys"]):
                            # Periodic sync of encryption keys
                            ID = topic[0]
                            self.log("Sync", "Recieved encryption key from agent ID: " + str(ID))
                            server_settings["Encryption Keys"][ID] = rsa.decrypt(message.payload, self.Private_Key).decode()
                            

                    if(typeofdata == "Status"):
                        # Get ID from session ID, recieved earlier
                        session_id = topic[0]
                        if(session_id in server_settings["Session ID"]):
                            ID = server_settings["Session ID"][session_id]
                            self.log("Agent", "Changing Online/Offline status for agent ID: " + str(ID))
                            add = ("UPDATE computers SET online=%s WHERE ID=%s")
                            data = (int(message.payload), ID)
                            cursor.execute(add, data)
                            self.mysql.commit()
                            cursor.close()

                    if(typeofdata == "Data"):
                        ID = topic[0]
                        title = topic[2]
                        # Get the encrptyion Key
                        if(ID in server_settings["Encryption Keys"]):
                            fernet = Fernet(server_settings["Encryption Keys"][ID])

                            if(title == "CMD"):
                                # Decrypt the payload
                                DecryptedData = json.loads(fernet.decrypt(message.payload).decode())
                                # Encrypt for PHP
                                if("Response" in DecryptedData):
                                    EncryptedData = self.encrypt(DecryptedData['Response'])
                                
                                    commandID = DecryptedData['Request']['commandID']
                                    self.log("CMD", "Command Received for: " + ID)
                                    add = ("UPDATE commands SET data_received=%s, time_received=NOW(), status=%s WHERE computer_id=%s AND ID=%s;")
                                    data = (EncryptedData, "Received", ID, commandID)
                                    cursor.execute(add, data)
                                    self.mysql.commit()
                                    cursor.close()

                            elif(title in server_settings["Computer Data"]):
                                loadType = topic[3]
                                # Decrypt the payload
                                if(server_settings["Computer Data"][title]["type"] == "raw"):
                                    DecryptedData = fernet.decrypt(message.payload)
                                else:
                                    DecryptedData = json.loads(fernet.decrypt(message.payload).decode())
                   
                                if(loadType == "Update"):
                                    if(ID not in server_settings["Computer Data"][title]["cache"]):
                                        server_settings["Computer Data"][title]["cache"][ID] = {}
                                        if(server_settings["Computer Data"][title]["changelog"] == True):
                                            # Cannot find existing data in Cache, So get data from SQL if exists
                                            query = "SELECT data FROM computer_data WHERE computer_id=%s AND name=%s AND data<>'' ORDER BY ID DESC LIMIT 1;"
                                            cursor.execute(query, (ID, title))
                                            result = cursor.fetchone()
                                            server_settings["Computer Data"][title]["cache"][ID] = json.loads(self.decrypt(result["data"].decode("UTF-8")))["Response"]

                                    if(ID in server_settings["Computer Data"][title]["cache"]):
                                        # Changelog
                                        if(server_settings["Computer Data"][title]["changelog"] == True): 
                                            # Process data and update array, then update full array to DB
                                            getDiff = DecryptedData['Response']
                                            result = (y for y in getDiff)
                                            try: # Add Diff to cache to get full result
                                                server_settings["Computer Data"][title]["cache"][ID] = patch(result, server_settings["Computer Data"][title]["cache"][ID])
                                            except: pass

                                        # Save result in DB, based on its prefered type
                                        if(server_settings["Computer Data"][title]["type"] == "raw"):
                                            data = DecryptedData
                                        else:
                                            data = json.dumps({"Request": DecryptedData['Request'], "Response": server_settings["Computer Data"][title]["cache"][ID]})
                                            data = self.encrypt(data) # Encrypt for PHP
                                            
                                        # Update Or Insert computer_data
                                        query = ("UPDATE computer_data set data=%s WHERE computer_id=%s AND name=%s LIMIT 1;")
                                        cursor.execute(query, (data, ID, title))

                                        if(cursor.rowcount == 0):
                                            query = ("INSERT INTO computer_data (computer_id, name, data) VALUES (%s, %s, %s);")
                                            cursor.execute(query, (ID, title, data))
                                            self.log("Data", "Agent " + str(ID) + ", Inserted " + title + ", Row: " + str(cursor.lastrowid))
                                        else:
                                            self.log("Data", "Agent " + str(ID) + ", Updated " + title)

                                        # Proccess Changelog
                                        try:
                                            if(server_settings["Computer Data"][title]["changelog"] == True):
                                                for (diff) in getDiff:
                                                    if(diff[0] == "change"):
                                                        query = ("INSERT INTO changelog (computer_id, computer_data_name, computer_data_key, old_value, new_value, change_type) VALUES(%s, %s, %s,%s, %s, %s);")
                                                        if(type(diff[1]) == list):  # Convert list of numbers to . delimited string, similar to php implode
                                                            string_ints = [str(int) for int in diff[1]]
                                                            diff[1] = ".".join(string_ints)
                                                        cursor.execute(query, (ID, title, diff[1], str(diff[2][0]), str(diff[2][1]), diff[0]))

                                                    elif(diff[0] == "add"):
                                                        query = ("INSERT INTO changelog (computer_id, computer_data_name, computer_data_key, old_value, new_value, change_type) VALUES(%s, %s, %s,%s, %s, %s);")
                                                        for (subdiff) in diff[2]:
                                                            cursor.execute(query, (ID, title, (str(diff[1]) + "." + str(subdiff[0])), "", str(subdiff[1]), "add"))        
                                        except Exception as e:
                                            exception_type, exception_object, exception_traceback = sys.exc_info()
                                            line_number = exception_traceback.tb_lineno
                                            if(server_settings["Server"]["debug"]): print(traceback.format_exc())
                                            self.log("OnMQTTMessage - " + title + " - line: " + str(line_number), e, "Error")
                                        
                                        self.mysql.commit()
                                        cursor.close() 
                                    else:
                                        return

                        elif(title == "heartbeat"): # Update missing keys when agent sends heartbeat
                            # Encryption key not found for this agent, asking for key
                            Setup["ID"] = str(ID)
                            Setup["Public_Key"] = self.Public_Key.save_pkcs1().decode('utf8')
                            self.mqtt.publish(str(ID) + "/Commands/Sync", json.dumps(Setup), qos=1, retain=False)
                        else:
                            print("Error - Title: Encryption, Message: No Encryption key found for agent ID: " + str(ID))

        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            line_number = exception_traceback.tb_lineno
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())
            self.log("OnMQTTMessage - Agent " + str(ID) + " - " + title + " - " + str(line_number), e, "Error")
    

    # Log: types: Info, Warn, Error
    def log(self, title, message, errorType="Info"):    
        try:
            logEvent = {}
            logEvent["Title"] = title 
            logEvent["Message"] = str(message)
            logEvent["Type"] = errorType
            logEvent["Time"] = str(datetime.datetime.now())
            server_settings["Server Log"].append(logEvent) 

            print(logEvent["Time"] + ": " + logEvent["Type"] + ", " + "Title: " + logEvent["Title"] + ", Message: " + logEvent["Message"])
            
            if(errorType != "Info"): # Only errors & warning are written to log file
                f = open(server_settings["Server"]["log_file"], "a")
                f.write(logEvent["Time"] + " " + logEvent["Type"] + " - " + "Title: " + logEvent["Title"] + ", Message: " + logEvent["Message"] + "\n")
                f.close()
            logEvent = None
        except Exception as e:
            print("Error saving to log file")
            print(e)
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())

    # source: https://gist.github.com/ahbanavi/ff3c0711b45f5056f821c00438af8f67
    def encrypt(self, data: dict) -> str:
        data_json_64 = base64.b64encode(json.dumps(data).encode('ascii'))
        try:
            key = binascii.unhexlify(b(server_settings["Server"]["php_encryption_key"]))
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(key, AES.MODE_GCM, iv)
            encrypted, tag = cipher.encrypt_and_digest(data_json_64)
            encrypted_64 = base64.b64encode(encrypted).decode('ascii')
            iv_64 = base64.b64encode(iv).decode('ascii')
            tag_64 = base64.b64encode(tag).decode('ascii')
            json_data = {'iv': iv_64, 'data': encrypted_64, 'tag': tag_64}
            return base64.b64encode(json.dumps(json_data).encode('ascii')).decode('ascii')
        except:  # noqa
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())
            return ''
        
    def decrypt(self, data) -> dict:
        try:
            key = binascii.unhexlify(b(server_settings["Server"]["php_encryption_key"]))
            encrypted = json.loads(base64.b64decode(str(data)).decode('ascii'))
            encrypted_data = base64.b64decode(encrypted['data'])
            iv = base64.b64decode(encrypted['iv'])
            tag = base64.b64decode(encrypted['tag'])
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt_and_verify(encrypted_data, tag)
            return json.loads(base64.b64decode(decrypted).decode('ascii'))
        except Exception as e:
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())
            return ''

    # This function updates the server stats of this 
    # server ONLY every 60 seconds and save it to the servers table in the DB 
    def stats(self, loop = False):
        try:
            self.mysql = pymysql.connect(user=server_settings["MySQL"]["username"], password=server_settings["MySQL"]["password"], host=server_settings["MySQL"]["host"], port=server_settings["MySQL"]["port"], database=server_settings["MySQL"]["database"], cursorclass=pymysql.cursors.DictCursor)
            with self.mysql:
                with self.mysql.cursor() as cursor:    
                    query = ("INSERT IGNORE INTO servers SET hostname=%s;")
                    cursor.execute(query, (os.environ['COMPUTERNAME'],))
                    self.mysql.commit()
                    cursor.close()

        except Exception as e:
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())

        loop_count = 0
        while(server_settings["Server"]["uptime"] == 0 or loop == True):
            try:
                time.sleep(30)
                loop_count += 1
                if(loop_count == 1): # Run every minute
                    loop_count = 0
                    server_settings["Server"]["uptime"] += 1
                    print("Info - Title: Updating Server Stats")
        
                    # General Stats
                    statistics = {
                        'status': 'Online',
                        'os': subprocess.check_output('ver', shell=True).decode("utf-8"),
                        'processor': platform.processor(),
                        'python_version': platform.python_version(),
                        'boot_time': psutil.boot_time(),
                        'cpu_count': psutil.cpu_count(),
                        'cpu_percent': psutil.cpu_percent(),
                        'cpu_stats': psutil.cpu_stats()._asdict(),
                        'disk_io_counters': psutil.disk_io_counters()._asdict(),
                        'disk_usage': [],
                        'net_io_counters': psutil.net_io_counters()._asdict(),
                        'net_adapters' : [],
                        'swap_memory': psutil.swap_memory()._asdict(),
                        'virtual_memory': psutil.virtual_memory()._asdict(),
                        'architecture': platform.architecture()[0],
                        'uptime': (server_settings["Server"]["uptime"] * 60),
                        'server_version': server_settings["Server"]["version"],
                        'mysql_server': server_settings["MySQL"]["host"] + ":" + str(server_settings["MySQL"]["port"]),
                        'mqtt_server': server_settings["MQTT"]["host"] + ":" + str(server_settings["MQTT"]["port"]),
                        'logs': server_settings["Server Log"][-100:] # send last 100
                    }

                    # Get Disk Status
                    try:
                        partitions = psutil.disk_partitions()
                        for p in partitions:
                            if p.mountpoint == "C:\\":
                                usage = psutil.disk_usage(p.mountpoint)
                                statistics['disk_usage'] = {
                                    'mountpoint': p.mountpoint,
                                    'total': usage.total,
                                    'used': usage.used,
                                    'percent': usage.percent
                                }
                    except: 
                        statistics['disk_usage'] = {}

                    # Get Network Adapters
                    try:
                        af_map = {socket.AF_INET: 'ipv4', socket.AF_INET6: 'ipv6', psutil.AF_LINK: 'mac'}
                        for nic, addrs in psutil.net_if_addrs().items():
                            adapters = {}
                            for addr in addrs:
                                adapters[af_map.get(addr.family, addr.family)] = addr.address
                                if(addr.netmask):
                                    adapters["netmask"] = addr.netmask
                            statistics['net_adapters'].append({nic: adapters})
                    except: 
                        statistics['net_adapters'] = []                       

                    # Update Server Status & Statistics in DB
                    self.mysql = pymysql.connect(user=server_settings["MySQL"]["username"], password=server_settings["MySQL"]["password"], host=server_settings["MySQL"]["host"], port=server_settings["MySQL"]["port"], database=server_settings["MySQL"]["database"], cursorclass=pymysql.cursors.DictCursor)
                    with self.mysql:
                        with self.mysql.cursor() as cursor:
                            query = ("UPDATE servers SET statistics=%s WHERE hostname=%s;")
                            cursor.execute(query, (json.dumps(statistics), os.environ['COMPUTERNAME']))
                            
                            query = "SELECT ID FROM servers WHERE hostname=%s ORDER BY ID DESC LIMIT 1;"
                            cursor.execute(query, (os.environ['COMPUTERNAME'],))
                            server_settings["Server"]["dbinfo"] = cursor.fetchone()
                            self.mysql.commit()
                            cursor.close()
                time.sleep(30)
            except Exception as e:
                if(server_settings["Server"]["debug"]): print(traceback.format_exc())

                
   
if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(OpenRMMServer)