#!/usr/bin/env python3

import re
import os
import time
import subprocess

def handle_lost_phys():
	if os.path.exists('/sys/class/ieee80211'):
		return os.listdir('/sys/class/ieee80211')
	return None
	
def iface_exists(iface):
	return os.path.exists(f"/sys/class/net/{iface}")

def iface_name_by_phy(phy):
	if os.path.exists(f"/sys/class/ieee80211/{phy}/device/net"):
		dir_list = os.listdir(f"/sys/class/ieee80211/{phy}/device/net")
		uevent_path = f"/sys/class/ieee80211/{phy}/device/net/{dir_list[0]}/uevent"
		if os.path.exists(uevent_path):
			with open(uevent_path, "r") as uevent:
				data = dict(line.strip().split('=') for line in uevent if "=" in line)
				return data.get('INTERFACE')
	return None

def get_phy_state(phy):
	iface = iface_name_by_phy(phy)
	iface_data = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
	return 'UP' in iface_data.stdout
	
def get_iface_state(iface):
	iface_data = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
	return 'UP' in iface_data.stdout

def set_phy_link(phy, state):
	states = ['up', 'down']
	iface = iface_name_by_phy(phy)
	
	if state in states:
		subprocess.run(['ip', 'link', 'set', iface, state])
		
def get_phy_driver(phy):
	if os.path.exists(f"/sys/class/ieee80211/{phy}/device/uevent"):
		with open(f"/sys/class/ieee80211/{phy}/device/uevent", "r") as uevent:
			data = dict(line.strip().split('=') for line in uevent if "=" in line)
			return data.get('DRIVER')
	return None

def get_phy_chipset(phy):
	iface = iface_name_by_phy(phy)
	if os.path.exists(f"/sys/class/ieee80211/{phy}/device/modalias"):
		modalias = open(f"/sys/class/ieee80211/{phy}/device/modalias", "r").read()			
		bus = modalias[:3]
			
		if bus == 'pci':
			businfo = subprocess.run(['ethtool', '-i', iface], capture_output=True, text=True)
			for line in businfo.stdout.splitlines():
				match = re.search('bus-info: [0-9]{4}:(.+)', line)
				if match:
					bus_id = match.group(1)
					if bus_id:
						lspci = subprocess.run(['lspci'], capture_output=True, text=True)
						for pcidev in lspci.stdout.splitlines():
							found_busid = pcidev[:7]
							if found_busid == bus_id:
								match = re.search(fr'{bus_id} .+: (.+)', pcidev)
								if match:
									chipset = match.group(1).replace('Wireless Adapter', '').strip()
									chipset = match.group(1).replace('Wireless Network Adapter', '').strip()
									return chipset

		if bus == 'usb':
			match = re.search(fr'{bus}:v([0-9A-Fa-f]{{4}})p([0-9A-Fa-f]{{4}})', modalias)
			if match:
				vid = match.group(1)
				pid = match.group(2)
				vid_pid = f"{vid}:{pid}".lower()
				lsusb = subprocess.run(['lsusb'], capture_output=True, text=True)
				for line in lsusb.stdout.splitlines():
					match = re.search(fr'ID {vid_pid} (.+)', line)
					if match:
						chipset = match.group(1).replace('Wireless Adapter', '').strip()
						#chipset = match.group(1).replace('Wireless Network Adapter', '').strip()
						return chipset

	return None

def get_phy_type(phy):
	iface = iface_name_by_phy(phy)
	iface_types = {
		0: 'Unknown',
		1: 'Station',
		802: 'Ad-Hoc',
		803: 'Monitor',
		804: 'Mesh (802.11s)',
		805: 'P2P (Direct GO)',
		806: 'P2P Client'
	}
	if os.path.exists(f"/sys/class/ieee80211/{phy}/device/net/{iface}/type"):
		iface_type = int(open(f"/sys/class/ieee80211/{phy}/device/net/{iface}/type", "r").read().strip())
		return iface_types.get(iface_type, 'Unknown')		
	return 'Unknown'

def set_phy_80211_monitor(phy):
	if get_phy_type(phy) != 'Monitor':
		iface = iface_name_by_phy(phy)
		set_phy_link(phy, 'down')
		time.sleep(1)
		if get_phy_state(phy) == False:
			#print(f"{phy} {iface} is down state")
			iface_index = 0
			mon_iface = f"radio{iface_index}mon"

			while iface_exists(mon_iface):
				mon_iface = f"radio{iface_index}mon"
				iface_index += 1

			subprocess.run(['iw', 'phy', phy, 'interface', 'add', mon_iface, 'type', 'monitor'], capture_output=True, text=True)
			subprocess.run(['iw', 'dev', iface, 'del'], capture_output=True, text=True)
			time.sleep(1)
			
			if get_phy_type(phy) == 'Monitor':
				set_phy_link(phy, 'up')
			else:
				subprocess.run(['iw', 'dev', mon_iface, 'del'], capture_output=True, text=True)
	
def set_phy_80211_station(phy):
	if get_phy_type(phy) == 'Monitor':
		iface = iface_name_by_phy(phy)
		set_phy_link(phy, 'down')
		if get_phy_state(phy) == False:
			station_iface = iface[:-3]
			subprocess.run(['iw', 'phy', phy, 'interface', 'add', station_iface, 'type', 'station'], capture_output=True, text=True)
			time.sleep(1)
			if os.path.exists(f"/sys/class/ieee80211/{phy}/device/net"):
				for phy_iface in os.listdir(f"/sys/class/ieee80211/{phy}/device/net"):
					mac_80211_type_path = f"/sys/class/ieee80211/{phy}/device/net/{phy_iface}/type"
					if os.path.exists(mac_80211_type_path):
						mac_80211_type = int(open(mac_80211_type_path, "r").read().strip())
						if mac_80211_type == 1:
							time.sleep(1)
							subprocess.run(['iw', 'dev', iface, 'del'], capture_output=True, text=True)

def get_phy_mac(phy):
	if os.path.exists(f"/sys/class/ieee80211/{phy}/macaddress"):
		return open(f"/sys/class/ieee80211/{phy}/macaddress", "r").read().strip()
	return 'Unknown'

def switch_iface_channel(interface, ch):
	subprocess.run(["iwconfig", interface, "channel", str(ch)], capture_output=True, text=True)

def get_phy_supported_channels(phydev):
	channels_data = subprocess.run(['iw', 'phy', phydev, 'channels'], capture_output=True, text=True).stdout
	channels = []
	for line in channels_data.splitlines():
		match = re.search('MHz \[(\d+)\]', line)
		if match:
			channels.append(int(match.group(1)))			
	return channels
