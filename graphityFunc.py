#!/usr/bin/env python


funcDict = { 
	'DRIVERCOMM': ['DeviceIoControl'],
	'CREATESTARTSERVICE': ['OpenSCManager', 'CreateService', 'OpenService', 'StartService'],
	'CREATETHREAD': ['CreateThread'],
	'PROCESSITER': ['CreateToolhelp32Snapshot', 'Process32First', 'Process32Next'],
	'APILOADING': ['LoadLibrary', 'GetProcAddress'],
	'APILOADING2': ['GetModuleHandle', 'GetProcAddress'],
	'WRITEFILE': ['CreateFile', 'WriteFile'],
	'READFILE': ['CreateFile', 'ReadFile'],
	'WINHOOK': ['SetWindowsHookEx'],
	'DRIVESITER': ['GetLogicalDriveStrings', 'GetDriveType'],
	'FILEITER': ['FindFirstFile', 'FindNextFile', 'FindClose'],
	'REGSETVAL': ['RegOpenKey', 'RegSetValue'],
	'REGQUERY': ['RegOpenKey', 'RegQueryValue'],
	'DUMPRSRC': ['FindResource', 'LoadResource', 'CreateFile', 'WriteFile'],
	'LOADRSRC': ['FindResource', 'LoadResource', 'LockResource'],
	'WSASEND': ['WSAStartup', 'gethostbyname', 'send'],
	'RECV': ['recv', 'send'],
	'RETROINJECTION': ['GetCurrentProcess', 'CreatePipe', 'DuplicateHandle'],
	'WINEXEC': ['WinExec'],
	'SHELLEXEC': ['ShellExecute'],
	'CREATEPROC': ['CreateProcess'],
	'WINDOW': ['CreateWindow', 'RegisterClass', 'DispatchMessage'],
	'EXITSYSTEM': ['ExitWindows'],
	'TEMPFILEWRITE': ['GetTempFileName', 'CreateFile', 'WriteFile'],
	'REMTHREAD': ['CreateThread', 'WriteProcessMemory', 'ReadProcessMemory', 'ResumeThread'],
	'FPRINT': ['fopen', 'fprintf', 'fclose'],
	'UPDATERESOURCE': ['BeginUpdateResource', 'UpdateResource', 'EndUpdateResource'],
	'SCREENSHOT': ['CreateCompatibleDC', 'GetDeviceCaps', 'CreateCompatibleBitmap', 'BitBlt'],
	'CRYPT': ['CryptAcquireContext', 'CryptEncrypt']
}




 
# TODO extend on those, and add moarrr:
# spawn a process
# execute a file
# move file, delete, create dir                                          -
# regenumkey
# createmutex
# fopen, fread, fwrite
# clipboard
# screen capture etc.

