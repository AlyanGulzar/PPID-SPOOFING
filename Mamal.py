import os
import time
import requests
import shutil
import winreg
from datetime import datetime

def simulate_file_drop():
    dropped_file = os.path.expanduser("~\\AppData\\Roaming\\important_docs.txt")
    with open(dropped_file, "w") as f:
        f.write("This file was dropped by fake malware at " + str(datetime.now()))
    print(f"[+] Dropped file at {dropped_file}")

def simulate_c2_communication():
    try:
        print("[*] Attempting to contact fake C2 server...")
        # Fake request to localhost (or replace with 127.0.0.1:4444 if you want to make a listener)
        requests.get("http://localhost:4444", timeout=2)
    except:
        print("[!] C2 server not reachable (simulated)")

def simulate_registry_write():
    try:
        key_path = r"Software\\FakeMalwareSimulation" # not simulated in registry :(
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValueEx(key, "Path", 0, winreg.REG_SZ, os.path.abspath(_file_))
        winreg.CloseKey(key)
        print(f"[+] Simulated persistence via registry (HKCU\\{key_path})")
    except Exception as e:
        print("[!] Failed to write registry key:", e)

def main():
    print("🛡  [Fake Malware Simulation Started]")
    simulate_file_drop()
    simulate_c2_communication()
    simulate_registry_write()

if _name_ == "_main_":
    main()