#!/usr/bin/env python3

#To DO:
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

# Check if required modules are installed, if not prompt the user
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

    #################################################
    # Function Name: SvcDoRun
    # Purpose: Initial starting point for this service
    # Example: None
    #################################################
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
        print("Version: " + server_settings["Server"]["version"])
        print("")

        self.isrunning = True
        self.log("Setup", "Generating RSA Keys")
        self.Public_Key, self.Private_Key = rsa.newkeys(2048)

        self.log("Setup", "Starting OpenRMM Server Setup")

        self.thread_stats = threading.Thread(target=self.stats, args=[True]).start() # Start the Stats() thread
        self.thread_renew_encryption_keys = threading.Thread(target=self.renew_encryption_keys, args=[]).start() # Start the Auto renew all encryption keys

        self.log("MQTT", "Connecting to MQTT")
        client_id = os.environ['COMPUTERNAME'] + "_" + str(randint(1000, 10000))
        self.mqtt = mqtt.Client(client_id=client_id, clean_session=True)
        self.mqtt.username_pw_set(server_settings["MQTT"]["username"], server_settings["MQTT"]["password"])
        self.mqtt.will_set("OpenRMM/Events/Server/Status", "", qos=1, retain=True) # Clear RSA Key when server dies
        self.mqtt.connect(server_settings["MQTT"]["host"], port=server_settings["MQTT"]["port"])
        self.mqtt.on_connect = self.on_connect
        self.mqtt.on_disconnect = self.on_disconnect
        self.mqtt.subscribe(server_settings["MQTT"]["topic"], qos=1)

        self.mqtt.message_callback_add("+/Agent/New", self.on_message_new_agent) # When new agents are installed
        self.mqtt.message_callback_add("+/Agent/Encryption/Update", self.on_message_agent_encryption_update) # When new agents are installed

        self.mqtt.message_callback_add("+/Agent/Status", self.on_message_agent_status) # When an agent goes Online/Offline
        self.mqtt.message_callback_add("+/Agent/Data/CMD", self.on_message_agent_cmd) # When an agent command prompt responce comes back
        self.mqtt.message_callback_add("+/Agent/Data/+/Update", self.on_message_agent_update) # When an agent sends new data
        self.mqtt.message_callback_add("+/Server/Command", self.on_message_server_command) # Front end commands sent to control server

        self.mqtt.loop_start()
        while self.isrunning: time.sleep(0.1)


    #################################################
    # Function Name: SvcStop
    # Purpose: Called when the service is stopped in Windows
    # Example: Services page->Stop Service
    #################################################
    def SvcStop(self):
        self.log("Service", "Stopping Service.")
        server_settings = None
        self.isrunning = False
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)  


    #################################################
    # Function Name: on_connect
    # Purpose: When MQTT connects or reconnects
    # Example: None
    #################################################
    def on_connect(self, client, userdata, flags, rc):
        try:
            self.log("MQTT", "Connected to server: " + server_settings["MQTT"]["host"] + " with result code: " + str(rc))
            self.log("MQTT", "Sending Event to Server/Status: Started")
            self.log("MQTT", "Updating RSA Public Key")
            self.mqtt.publish("OpenRMM/Events/Server/Status", "Started", qos=1, retain=True)
            self.mqtt.publish("OpenRMM/Configuration/Encryption/RSA/Keys/Public", self.Public_Key.save_pkcs1().decode('utf8'), qos=1, retain=True)
        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            line_number = exception_traceback.tb_lineno
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())
            self.log("MQTT " + str(line_number), e, "Error")


    #################################################
    # Function Name: on_disconnect
    # Purpose: When MQTT Disconnects from MQTT server
    # Example: Server goes offline
    #################################################
    def on_disconnect(self, client, userdata, rc):
        self.log("MQTT", "Unexpected disconnection.", "Warn")


    #################################################
    # Function Name: on_message_server_command
    # Purpose: When a command is recieved from the front end
    # Example: 1\Server\Command->payload: shutdown, restart, stop service, restart service
    #################################################
    def on_message_server_command(self, client, userdata, message):
        try:
            #print("MQTT: Received message '" + str(message.payload) + "' on topic '" + message.topic + "' with QoS " + str(message.qos))      
            ID = message.topic.split("/")[0]
            if("ID" in server_settings["Server"]["dbinfo"]):
                if(server_settings["Server"]["dbinfo"]["ID"] == int(ID)):
                    command = json.loads(message.payload)
                    self.Commands(command["payload"])
        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            line_number = exception_traceback.tb_lineno
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())
            self.log("MQTT Message - Server Command, Server: " + str(ID) + " - Line: " + str(line_number), e, "Error")


    #################################################
    # Function Name: on_message_new_agent
    # Purpose: When an MQTT message is recieved from a new agent
    # Example: New Agent installed
    #################################################
    def on_message_new_agent(self, client, userdata, message):
        try:
            ID = None
            self.mysql = pymysql.connect(user=server_settings["MySQL"]["username"], password=server_settings["MySQL"]["password"], host=server_settings["MySQL"]["host"], port=server_settings["MySQL"]["port"], database=server_settings["MySQL"]["database"], cursorclass=pymysql.cursors.DictCursor)
            with self.mysql:
                with self.mysql.cursor() as cursor:
                    hostname = message.topic.split("/")[0]
                    # Generate Encryption Key Here, then encrypt all data with AES, send the encryption key encoded with public key given by server
                    self.log("Setup New Agent", "Computer not found, adding as a new computer")
                    add = ("INSERT INTO computers () VALUES()")
                    cursor.execute(add)
                    ID = cursor.lastrowid
                    self.mysql.commit()
                    
                    self.log("New Agent", "Added New Computer, ID: " + str(ID))
                    Setup = {"ID":str(ID)}
                    self.mqtt.publish(hostname + "/Commands/New", json.dumps(Setup), qos=1, retain=False)
        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            line_number = exception_traceback.tb_lineno
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())
            self.log("MQTT Message - New Agent, Agent: " + str(ID) + " - Line: " + str(line_number), e, "Error")


    #################################################
    # Function Name: on_message_agent_encryption_update
    # Purpose: When the agent sends us the encrption key
    # Example: Agent startup, computer reboot, manual key refresh
    #################################################
    def on_message_agent_encryption_update(self, client, userdata, message):
        try:
            ID = message.topic.split("/")[0]
            self.log("Ready", "Recieved encryption key from agent ID: " + ID)
            server_settings["Encryption Keys"][ID] = rsa.decrypt(message.payload, self.Private_Key).decode()
        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            line_number = exception_traceback.tb_lineno
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())
            self.log("MQTT Message - Agent Encryption Update, Agent: " + str(ID) + " - Line: " + str(line_number), e, "Error")  


    #################################################
    # Function Name: on_message_agent_status
    # Purpose: When an MQTT message is recieved from an agent or last will
    # Example: Online/Offline
    #################################################
    def on_message_agent_status(self, client, userdata, message):
        try:
            self.mysql = pymysql.connect(user=server_settings["MySQL"]["username"], password=server_settings["MySQL"]["password"], host=server_settings["MySQL"]["host"], port=server_settings["MySQL"]["port"], database=server_settings["MySQL"]["database"], cursorclass=pymysql.cursors.DictCursor)
            with self.mysql:
                with self.mysql.cursor() as cursor:
                    ID = message.topic.split("/")[0]
                    self.log("Agent", "Changing Online/Offline status for agent ID: " + str(ID))
                    add = ("UPDATE computers SET online=%s WHERE ID=%s")
                    data = (int(message.payload), ID)
                    cursor.execute(add, data)
                    self.mysql.commit()
                    cursor.close()
        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            line_number = exception_traceback.tb_lineno
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())
            self.log("MQTT Message - Agent Status, Agent: " + str(ID) + " - Line: " + str(line_number), e, "Error")


    #################################################
    # Function Name: on_message_agent_cmd
    # Purpose: When the agent sends its command prompt response
    # Example: CMD is opend and used in web UI
    #################################################
    def on_message_agent_cmd(self, client, userdata, message):
        try:
            self.mysql = pymysql.connect(user=server_settings["MySQL"]["username"], password=server_settings["MySQL"]["password"], host=server_settings["MySQL"]["host"], port=server_settings["MySQL"]["port"], database=server_settings["MySQL"]["database"], cursorclass=pymysql.cursors.DictCursor)
            with self.mysql:
                with self.mysql.cursor() as cursor:
                    ID = message.topic.split("/")[0]

                    # Get the encrptyion Key
                    if(ID in server_settings["Encryption Keys"]):
                        fernet = Fernet(server_settings["Encryption Keys"][ID])
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
        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            line_number = exception_traceback.tb_lineno
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())
            self.log("MQTT Message - Agent CMD, Agent: " + str(ID) + " - Line: " + str(line_number), e, "Error")


    #################################################
    # Function Name: on_message_agent_update
    # Purpose: When an MQTT message is recieved from an agent with new data
    # Example: Timed data updates or manual refresh from webui
    #################################################
    def on_message_agent_update(self, client, userdata, message):
        try:
            self.mysql = pymysql.connect(user=server_settings["MySQL"]["username"], password=server_settings["MySQL"]["password"], host=server_settings["MySQL"]["host"], port=server_settings["MySQL"]["port"], database=server_settings["MySQL"]["database"], cursorclass=pymysql.cursors.DictCursor)
            with self.mysql:
                with self.mysql.cursor() as cursor:
                    ID = message.topic.split("/")[0]
                    title = message.topic.split("/")[3] # Example: sound_devices, pnp_entities

                    if(ID in server_settings["Encryption Keys"]):
                        fernet = Fernet(server_settings["Encryption Keys"][ID])

                        if(title in server_settings["Computer Data"]):
                    
                            # Decrypt the payload
                            if(server_settings["Computer Data"][title]["type"] == "raw"):
                                DecryptedData = fernet.decrypt(message.payload)
                            else:
                                DecryptedData = json.loads(fernet.decrypt(message.payload).decode())
                            
                            if(ID not in server_settings["Computer Data"][title]["cache"]):
                                server_settings["Computer Data"][title]["cache"][ID] = {}
                                if(server_settings["Computer Data"][title]["changelog"] == True):
                                    # Cannot find existing data in Cache, So get data from SQL if exists
                                    query = "SELECT data FROM computer_data WHERE computer_id=%s AND name=%s AND data<>'' ORDER BY ID DESC LIMIT 1;"
                                    cursor.execute(query, (ID, title))
                                    
                                    if(cursor.rowcount > 0):
                                        result = cursor.fetchone()
                                        server_settings["Computer Data"][title]["cache"][ID] = json.loads(self.decrypt(result["data"].decode("UTF-8")))["Response"]
                                    else:
                                        server_settings["Computer Data"][title]["cache"][ID] = {}

                            if(ID in server_settings["Computer Data"][title]["cache"]):
                                # Changelog
                                if(server_settings["Computer Data"][title]["changelog"] == True): 
                                    # Process data and update array, then update full array to DB
                                    getDiff = DecryptedData['Response']
                                    result = (y for y in getDiff)
                                    try: # Add Diff to cache to get full result
                                        server_settings["Computer Data"][title]["cache"][ID] = patch(result, server_settings["Computer Data"][title]["cache"][ID])
                                    except Exception as e: pass

                                # Save result in DB, based on its prefered type
                                if(server_settings["Computer Data"][title]["type"] == "raw"):
                                    data = DecryptedData
                                else:
                                    data = json.dumps({"Request": DecryptedData['Request'], "Response": server_settings["Computer Data"][title]["cache"][ID]})
                                    data = self.encrypt(data) # Encrypt for PHP
                                
                                # Check if we need to update or insert
                                query = "SELECT ID FROM computer_data WHERE computer_id=%s AND name=%s ORDER BY ID DESC LIMIT 1;"
                                cursor.execute(query, (ID, title))
                                result = cursor.fetchall()
                                if(len(result) > 0):
                                    # Update Or Insert computer_data
                                    query = ("UPDATE computer_data set data=%s WHERE computer_id=%s AND name=%s LIMIT 1;")
                                    cursor.execute(query, (data, ID, title))
                                    self.log("Data", "Agent " + str(ID) + ", Updated " + title)
                                else:
                                    query = ("INSERT INTO computer_data (computer_id, name, data) VALUES (%s, %s, %s);")
                                    cursor.execute(query, (ID, title, data))
                                    self.log("Data", "Agent " + str(ID) + ", Inserted " + title + ", Row: " + str(cursor.lastrowid))
                
                            
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
                                    self.log("MQTT Message, Changelog - " + title + " - Line: " + str(line_number), e, "Error")
                                
                                self.mysql.commit()
                                cursor.close() 
                            else:
                                return
        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            line_number = exception_traceback.tb_lineno
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())
            self.log("MQTT Message - Agent Update, Agent: " + str(ID) + " - " + title + " - Line: " + str(line_number), e, "Error")
    

    #################################################
    # Function Name: Commands
    # Purpose: Commands sent from the front end, to control the server
    # Example: shutdown, restart, stop service, restart service
    #################################################
    def Commands(self, command):
        try:
            self.log("Commands", "Running command: " + str(command))
            if command == 'stop service':
                win32serviceutil.StopService(server_settings["Service"]["name"])
            elif command == 'restart service':
                os.execv(sys.argv[0], sys.argv)
            elif command == 'shutdown':
                data = str(subprocess.check_output("shutdown /s /f /t 60", shell=True), "utf-8")
                data = None
            elif command == 'update':
                pass
            elif command == 'renew_keys':
                self.log("Commands", "Generating RSA Keys")
                self.Public_Key, self.Private_Key = rsa.newkeys(2048)
                self.mqtt.publish("OpenRMM/Configuration/Encryption/RSA/Keys/Public", self.Public_Key.save_pkcs1().decode('utf8'), qos=1, retain=True)
            elif command == 'restart':
                data = str(subprocess.check_output("shutdown /r /f /t 30", shell=True), "utf-8")
                data = None
        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            line_number = exception_traceback.tb_lineno
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())
            self.log("Commands, Line: " + str(line_number), e, "Error")


    #################################################
    # Function Name: log
    # Purpose: To log to warn & errors to file and send all to front end
    # Example: log("test", "this is a test", Info), types: Info, Warn, Error
    #################################################
    def log(self, title, message, errorType="Info"):    
        try:
            logEvent = {}
            logEvent["Title"] = title 
            logEvent["Message"] = str(message)
            logEvent["Type"] = errorType
            logEvent["Time"] = str(datetime.datetime.now().strftime("%m-%d-%y %I:%M:%S %p"))
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

 
    #################################################
    # Function Name: encrypt
    # Purpose: To encrpt data before adding it to MySQL
    # Example: Data saved to MySQL for use in PHP
    # Source: https://gist.github.com/ahbanavi/ff3c0711b45f5056f821c00438af8f67
    #################################################
    def encrypt(self, data: dict) -> str:
        data_json_64 = base64.b64encode(json.dumps(data).encode('ascii'))
        try:
            key = binascii.unhexlify(str.encode(server_settings["Server"]["php_encryption_key"]))
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(key, AES.MODE_GCM, iv)
            encrypted, tag = cipher.encrypt_and_digest(data_json_64)
            encrypted_64 = base64.b64encode(encrypted).decode('ascii')
            iv_64 = base64.b64encode(iv).decode('ascii')
            tag_64 = base64.b64encode(tag).decode('ascii')
            json_data = {'iv': iv_64, 'data': encrypted_64, 'tag': tag_64}
            return base64.b64encode(json.dumps(json_data).encode('ascii')).decode('ascii')
        except Exception as e:  # noqa
            if(server_settings["Server"]["debug"]): print(traceback.format_exc())
            return ''
        
    #################################################
    # Function Name: decrypt
    # Purpose: To decrpt data recieved from MySQL
    # Example: Data saved to MySQL for use in PHP
    # Source: https://gist.github.com/ahbanavi/ff3c0711b45f5056f821c00438af8f67
    #################################################
    def decrypt(self, data) -> dict:
        try:
            key = binascii.unhexlify(str.encode(server_settings["Server"]["php_encryption_key"]))
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


    #################################################
    # Function Name: renew_encryption_keys
    # Purpose: Update the RSA keys & each agents salt
    # Example: Reset all encryptopn keys after 7 days
    #################################################
    def renew_encryption_keys(self):
        try:
            loop_count = 0
            while(True):
                time.sleep(86400) # 1 day
                loop_count += 1
                if(loop_count == 7):
                    loop_count = 0
                    self.Commands("renew_keys")
        except: pass
            

    #################################################
    # Function Name: stats
    # Purpose: Updates the server stats in MySQL every 60 seconds
    # Example: Data can be seen in front end
    #################################################
    def stats(self, loop = False):
        loop_count = 0
        while(server_settings["Server"]["uptime"] == 0 or loop == True):
            try:
                time.sleep(30)
                loop_count += 1
                if(loop_count == 1): # Run every minute
                    loop_count = 0
                    server_settings["Server"]["uptime"] += 1
                    print(str(datetime.datetime.now().strftime("%m-%d-%y %I:%M:%S %p")) + ": Info, Updating Server Stats")
        
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
                            query = ("INSERT INTO servers (hostname, statistics) VALUES (%s, %s) ON DUPLICATE KEY UPDATE statistics=%s")
                            cursor.execute(query, (os.environ['COMPUTERNAME'], json.dumps(statistics), json.dumps(statistics)))
                            
                            query = "SELECT ID FROM servers WHERE hostname=%s ORDER BY ID DESC LIMIT 1;"
                            cursor.execute(query, (os.environ['COMPUTERNAME'],))
                            server_settings["Server"]["dbinfo"] = cursor.fetchone()
                            self.mysql.commit()
                            cursor.close()
                
                time.sleep(30)
            except Exception as e:
                exception_type, exception_object, exception_traceback = sys.exc_info()
                line_number = exception_traceback.tb_lineno
                if(server_settings["Server"]["debug"]): print(traceback.format_exc())
                self.log("Stats, Line: " + str(line_number), e, "Error")


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(OpenRMMServer)