# Since javascript files linked in with other web-related/front related files has trouble importing external sources
# this python will act as a medium of communication between the data file, back-end c++ and front-end javascript
#
# As of right now, this is the envisioned model:
# 
# Opening the app runs this file which:
#   1. Opens the frontend files via eel
#   2. Finds media for potential packet analysis
#   3. Opens csv file for reading data
#
# This program then waits for the front end javascript to: 
#   1. Request opening an external csv file by a file path. In response, this program will open the
#      file contents and send it to the javascript file to display.
#   2. Request to capture traffic. In response, this program will run the c++ file which saves the data
#      csv file. This program will read the data from the csv file and send it to the javascript to display
#   3. Log-in to network media?

import eel
import platform
import subprocess
import psutil
import os.path
import pandas as pd

eel.init("frontend")
eel.start("main.html")

# Check OS and find appropriate host lists
sys = platform.system()

datafile = open("data/data.csv", "w+")

# helper functions

# partially parses by seperating each data entry into an individual element in the list 
def parse_csv(filename):
    entries = []
    data = pd.read_csv(filename)

    # Check formatting
    headers = list(data)
    if headers[0] != "src" or headers[1] != "dest" or headers[2] != "msgproc" or headers[3] != "size" or headers[4] != "payload":
        return None
    
    for row in data.index:
        entries.append(data["src"][row])
        entries.append(data["dest"][row])
        entries.append(data["msgproc"][row])
        entries.append(data["size"][row])
        entries.append(data["payload"][row])
    return entries

# exposed functions called by javascript
@eel.expose
def clear_data():
    datafile.truncate(0)
    datafile.write("src,dest,msgproc,size,payload\n")

@eel.expose
def get_file(filename):
    if os.path.isfile(filename):
        # Close old data file
        datafile.close()
        # Open new data file
        datafile = open(filename, "w+")
        return parse_csv(datafile.readlines())
    return None

@eel.expose
def get_interface_names():
    return list(psutil.net_if_addrs().keys())

@eel.expose
def start_capture():
    if sys == "Windows":
        hostfile = open("C:/Windows/System32/Drivers/etc/hosts", "r")
        # subprocess.check_call("start {compiled cpp file}")
        hostfile.close()
    elif sys == "Linux":
        hostfile = open("/etc/hosts", "r")
        # subprocess.check_call("./{compiled cpp file}")
        hostfile.close()
    elif sys == "Darwin": # I think this is what a mac OS is detected as
        hostfile = open("/private/etc/hosts", "r")
        # subprocess.check_call(idk ill figure it out later)
        hostfile.close()
    else: # Unsupported OS
        print("OS not supported")

@eel.expose 
def stop_capture():
    print("placeholder")
    
datafile.close()