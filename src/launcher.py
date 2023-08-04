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
import time
import os.path

eel.init("frontend")
eel.start("main.html")

# Check OS and find appropriate host lists
# This is done mostly to find localhost
sys = platform.system()
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

datafile = open("data/data.csv", "w+")

# helper functions

# partially parses by seperating each data entry into an individual element in the list 
def parse_csv(raw_data):
    parsed_data = []
    for line in raw_data:
        item = ""
        inquotes = False
        for i in range(0,len(line)-1):
            char = line[i]

            # if the current character is a double quotation and the next is a comma, the next character after the comma will be the first of the next item
            inquotes = char == "\"" and (len(line) > i + 1 and line[i+1] != ",") or (char != "\"" and (len(line) > i + 1 and line[i+1] != ","))

            if char == "," and not inquotes: # means there is a new data item
                parsed_data.append(item)
                item = ""
            else:
                item += char

    return parsed_data
                
        

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

datafile.close()