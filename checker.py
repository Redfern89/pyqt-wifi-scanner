#!/usr/bin/env python3

import os
import sys
import shutil
import time

def is_linux_platform():
	return sys.platform.startswith("linux")

def run_as_root():
	return os.geteuid() == 0

def is_installed(cmd):
	return shutil.which(cmd) is not None

def check_need_pkg():
	result = True
	for pkg in ['ethtool', 'iw', 'ip', 'lspci', 'lsusb', 'ifconfig', 'iwconfig', 'rfkill']:
		installed = 'OK' if is_installed(pkg) else 'NOT'
		if installed == 'NOT':
			result = False
		print(f"Checking for {pkg} - {installed}")
		time.sleep(0.1)

	return result

def check_all_need():
	print("--- Welcome to GUI WiFi scaner! ---")
	if not is_linux_platform():
		print('For Linux only. Aborted')
		sys.exit(1)
	else:
		print('Checking platform - OK')
	
	if not run_as_root():
		print('Please, run as root. Aborted')
		sys.exit(1)
	else:
		print('Checking root - OK')

	print('Checked packakes...')
	return check_need_pkg()
