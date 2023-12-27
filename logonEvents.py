import ctypes
import csv
import os
import sys
import win32evtlog
import win32con

# Function to check for admin rights
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Function to get logon events and save them to a CSV
def get_logon_events(logon_types):
    # Open the Security event log
    server = 'localhost'
    logtype = 'Security'
    hand = win32evtlog.OpenEventLog(server, logtype)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    # Open a file to save the events
    with open('logon_events.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["TimeGenerated", "EventID", "LogonType", "TargetUserName"])

        try:
            while True:
                # Read the events
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break

                for event in events:
                    if event.EventID == 4624:
                        data = event.StringInserts
                        if data and data[8] in logon_types:
                            writer.writerow([event.TimeGenerated.Format(), event.EventID, data[8], data[5]])
        finally:
            win32evtlog.CloseEventLog(hand)

# Main code
if is_admin():
    # Code to run as admin
    logon_types = ['2', '7', '10']
    get_logon_events(logon_types)
   
else:
    # Re-run the program with admin rights
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
