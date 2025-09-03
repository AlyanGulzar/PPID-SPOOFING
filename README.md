#  PPID Spoofing (Process Injection Simulation)

This project demonstrates **Parent Process ID (PPID) Spoofing** on Windows, a common **malware defense evasion technique**.  
It was developed as part of an academic project on **Operating System Security and Malware Simulation**.

## 📖 What is PPID Spoofing?
Attackers use PPID Spoofing to make a malicious process appear as if it was spawned by a **legitimate parent process** such as `explorer.exe` or `winlogon.exe`.  
This tricks security tools, bypasses naive detection methods, and helps malware blend into normal system activity.

### Example:
- Instead of showing `mamal.exe` launched directly, the malware appears to be a child of `explorer.exe`.  
- This hides it from **basic process ancestry checks** and some EDR solutions.

---

## ⚙️ How It Works
- Uses the **Windows API** function `CreateProcessW` with the flag `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.
- Spoofs the parent process handle (e.g., `explorer.exe` PID).
- Launches the payload (`mamal.exe`) under the spoofed parent process.
- Tested on Windows with **Python 3**, `pywin32`, and `psutil`.

---

## 📂 Project Files
- `Spoof.py` → Main script for PPID spoofing.
- `OS Project Report.pdf` → Full academic report with explanation and findings.
- `OS Project Presentation.pptx` → Slides covering live demo, countermeasures, and OPSEC lessons.

---

## 🚀 Usage

> ⚠️ **Disclaimer**: This code is for **educational and research purposes only**.  
> Do **NOT** use it on systems without explicit permission. Misuse may violate laws.

1. Clone the repository:
   ```bash
   git clone https://github.com/AlyanGulzar/PPID-SPOOFING.git
   cd PPID-SPOOFING
2. Install dependencies:
   ```bash
   pip install psutil pywin32
3. Run the script
   ```bash
   python Spoof.py
4. The script:
   • Locates a trusted process (explorer.exe, winlogon.exe, or services.exe).
   • Creates a new process (mamal.exe by default) with a spoofed parent PID.
   • Verify via Task Manager or Process Explorer → The new process will appear as if launched by the trusted parent.

## 🔍 Detection & Defense

- Monitor `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` calls.  
- Alert if `explorer.exe` spawns unusual children.  
- Hunt for **PPID and binary path mismatches**.  
- Apply **EDR/SIEM rules** and process integrity checks.  

---

## 📚 References

- [Microsoft CreateProcessW Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)  
- [ATT&CK Technique: Process Injection](https://attack.mitre.org/techniques/T1055/)  
- APT groups like **Lazarus**, **FIN7**, and **DarkSide** use PPID spoofing in the wild.  

---

## 👥 Project Team

- Alyan Gulzar  
- Bisma Raees  
- Ayesha
- Adan Talat  

---
