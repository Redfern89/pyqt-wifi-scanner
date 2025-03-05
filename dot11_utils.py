#!/usr/bin/env python3

from scapy.all import *

def get_chip_vendor(pkt: bytes) -> str:
	vendors_oui = {
		0x001018: "Broadcom",  # Broadcom
		0x00037f: "AtherosC",  # Atheros Communications
		0x001374: "AtherosC",  # Atheros Communications
		0x00B052: "AtherosC",  # Atheros Communications
		0x000c43: "RalinkTe",  # Ralink Technology, Corp.
		0x0017a5: "RalinkTe",  # Ralink Technology, Corp.
		0x00e04c: "RealtekS",  # Realtek Semiconductor Corp.
		0x00a000: "Mediatek",  # Mediatek Corp.
		0x000ce7: "Mediatek",  # Mediatek Corp.
		0x001c51: "CelenoCo",  # Celeno Communications, Inc
		0x005043: "MarvellS",  # Marvell Semiconductor, Inc.
		0x002686: "Quantenn",  # Quantenna Communications, Inc
		0x000986: "LantiqML",  # Lantiq/MetaLink
		0x0050f2: "Microsof",  # Microsoft
		0xac853d: "HuaweiTe",  # Huawei Technologies Co., Ltd
		0x88124e: "Qualcomm",  # Qualcomm Atheros
		0x8cfdf0: "Qualcomm",  # Qualcomm, Inc
		0x00a0cc: "Lite-OnC",  # Lite-On Communications, Inc
		0x4045da: "SpreadTe",  # Spreadtrum Technology, Inc
		0x506f9a: "Wi-FiAli"   # Wi-Fi Aliance
	}

	index = 0
	signature = ''
	vendor_oui_marker = 0xDD
	vendor_start_sign_padding = 2
	vendor_end_sign_padding = 5
	vendor_len_padding = 3
	vendor_len_min = 6
	vendor_len_max = 9

	while index < len(pkt):
		packet_raw = pkt[index]
		if packet_raw == vendor_oui_marker:
			vendor_id_length = pkt[index +1]
			if index + vendor_len_padding <= len(pkt):
				if vendor_len_min <= vendor_id_length <= vendor_len_max and index + vendor_end_sign_padding <= len(pkt):
					vendor_bytes = pkt[index+vendor_start_sign_padding:index+vendor_end_sign_padding]
					vendor_id = int.from_bytes(vendor_bytes, byteorder="big")
					signature = f"\"0x{vendor_id:06x}\""
					return vendors_oui.get(vendor_id, f"Unknown signature {signature}")
		index += 1

	return "Unknown"

def get_wifi_encryption(pkt):
	wep = False
	rsn_info = False
	wpa_info = False

	elt = pkt.getlayer(Dot11Elt)
	while elt:
		if elt.ID == 48:
			rsn_info = elt.info
		elif elt.ID == 221 and elt.info.startswith(b'\x00\x50\xF2\x01'):
			wpa_info = elt.info
		elt = elt.payload.getlayer(Dot11Elt)

	if pkt.haslayer(Dot11Beacon):
		if pkt[Dot11Beacon].cap & 0x10:
			wep = True
		
	if pkt.haslayer(Dot11ProbeResp):
		if pkt[Dot11ProbeResp].cap & 0x10:
			wep = True

	if rsn_info:
		akm_count = int.from_bytes(rsn_info[10:12], "little")
		akm_list = rsn_info[12:12 + (akm_count * 4)]
		
		if b'\x00\x0f\xac\x08' in akm_list:
			return 'WPA3'
		else:
			return 'WPA2'
	elif wpa_info:
		return 'WPA'
	elif wep:
		return 'WEP'
	else:
		return 'Open'
		
def get_wifi_akm_info(pkt):
	rsn_info = None
	wpa_info = None
	
	cipher_suites = {
		0x00: "Group",
		0x01: "WEP-40",
		0x02: "TKIP",
		0x03: "WRAP",
		0x04: "CCMP",
		0x05: "WEP-104",
		0x06: "CMAC-128",
		0x07: "CMAC-128",
		0x08: "GCMP-128",
		0x09: "GCMP-256",
		0x0A: "BIP-GMAC-128",
		0x0B: "BIP-GMAC-256",
		0x0C: "BIP-CMAC-128",
		0x0D: "BIP-CMAC-256"
	}

	akm_suites = {
		0x01: "802.1X (RSNA)",
		0x02: "PSK",
		0x03: "802.1X-FT (Fast Transition)",
		0x04: "PSK-FT",
		0x05: "802.1X-PMKSA (PMSK)",
		0x06: "802.1X-PSK",
		0x07: "802.1X-TDLS",
		0x08: "SAE",
		0x09: "SAE-FT",
		0x0A: "PSK-SHA256",
		0x0B: "802.1X-SHA256",
		0x0C: "SAE-SHA384 (WPA3-Enterprise 192-bit)",
		0x0D: "802.1X-FT-SHA384"
	}	
	
	elt = pkt.getlayer(Dot11Elt)
	group = ''
	ciphers = []
	akms = []
	
	while elt:
		if elt.ID == 48:
			rsn_info = elt.info
		elif elt.ID == 221 and elt.info.startswith(b'\x00\x50\xF2\x01'):
			wpa_info = elt.info
		elt = elt.payload.getlayer(Dot11Elt)

	'''
		Example data input:
		x00\x50\xF2 \x01 \x01\x00 \x00\x50\xF2 \x02 \x02\x00 \x00\x50\xF2 \x02 \x00\x50\xF2 \x04 \x01\x00 \x00\x50\xF2 \x02
		
		Data structure:
		\x00\x50\xF2	- Vendor OUI (Microsoft)
		\x01			- Vendor OUI Type (WPA)
		\x01\x00		- WPA version (1)
		\x00\x50\xF2	- Multicast cipher suite (Microsoft)
		\x02			- Multicast cipher suite type (TKIP)
		\x02\x00		- Unicast cipher suite count (2)
		\x00\x50\xF2	- 1. Multicast cipher suite item vendor (Microsoft)
		\x02			- 1. Multicast cipher suite item type (TKIP)
		\x00\x50\xF2	- 2. Multicast cipher suite item vendor (Microsoft)
		\x04			- 2. Multicast cipher suite item type (AES (CCM))
		\x01\x00		- Auth key management (AKM) suite count (1)
		\x00\x50\xF2	- 1. Auth key management suite vendor (Microsoft)
		\x02			- 1. Auth key management suite type (PSK)
	'''
	
	if wpa_info:
		multicast_cipher_suite_offset = 6
		multicast_cipher_suite = wpa_info[multicast_cipher_suite_offset:multicast_cipher_suite_offset+4]
		multicast_cipher_suite_vendor = multicast_cipher_suite[:3]
		multicast_cipher_suite_id = int.from_bytes(multicast_cipher_suite[3:])
		unicast_cipher_suite_count_offset = 10
		unicast_cipher_suite_count = int.from_bytes(wpa_info[unicast_cipher_suite_count_offset:unicast_cipher_suite_count_offset+2], "little")
		unicast_cipher_suite_list_offset = unicast_cipher_suite_count_offset + 2
		akm_count_offset = unicast_cipher_suite_list_offset + (unicast_cipher_suite_count * 4)
		akm_count = int.from_bytes(wpa_info[akm_count_offset:akm_count_offset+2], "little")
		akm_list_offset = akm_count_offset + 2
		
		group = cipher_suites.get(multicast_cipher_suite_id, 'Unknown')
		
		for i in range(akm_count):
			akm_list_item = wpa_info[i * 4 + akm_list_offset:i * 4 + (akm_list_offset + 4)]
			akm_list_item_vendor = int.from_bytes(akm_list_item[:3])
			akm_list_item_id = int.from_bytes(akm_list_item[3:])
			akms.append(akm_suites.get(akm_list_item_id, 'Unknown'))
		
		for i in range(unicast_cipher_suite_count):
			unicast_cipher_suite_item = wpa_info[i * 4 + unicast_cipher_suite_list_offset:i * 4 + (unicast_cipher_suite_list_offset + 4)]
			unicast_cipher_suite_vendor = int.from_bytes(unicast_cipher_suite_item[:3])
			unicast_cipher_suite_id = int.from_bytes(unicast_cipher_suite_item[3:])
			ciphers.append(cipher_suites.get(unicast_cipher_suite_id, 'Unknown'))

	elif rsn_info:
		group_cipher_suite_vendor = int.from_bytes(rsn_info[2:5], "big")
		group_cipher_suite_type = int.from_bytes(rsn_info[5:6], "little")
		pairwise_suite_count = int.from_bytes(rsn_info[6:8], "little")
		pairwise_suite_list_offset = 8
		akm_count_offset = pairwise_suite_list_offset + (pairwise_suite_count * 4)
		akm_list_offset = akm_count_offset + 2
		akm_count = int.from_bytes(rsn_info[akm_count_offset:akm_list_offset], "little")
		
		group = cipher_suites.get(group_cipher_suite_type, 'Unknown')
		
		for i in range(akm_count):
			akm_list_item = rsn_info[i * 4 + akm_list_offset:i * 4 + (akm_list_offset + 4)]
			akm_list_item_vendor = akm_list_item[:3]
			akm_list_item_type = int.from_bytes(akm_list_item[3:])
			akms.append(akm_suites.get(akm_list_item_type, 'Unknown'))
		for i in range(pairwise_suite_count):
			pairwise_suite_list_item = rsn_info[i * 4 + pairwise_suite_list_offset:i * 4 + (pairwise_suite_list_offset + 4)]
			pairwise_suite_list_item_vendor = pairwise_suite_list_item[:3]
			pairwise_suite_list_item_type = int.from_bytes(pairwise_suite_list_item[3:])
			ciphers.append(cipher_suites.get(pairwise_suite_list_item_type, 'Unknown'))
	result = {
		'group': group,
		'akms': akms,
		'ciphers': ciphers
	}
	return result

def parse_wps_version(wps_ie):
    i = 4
    wps_version = None
    wps_2_0_flag = False
    while i < len(wps_ie):
        if len(wps_ie) < i + 4:
            break
        field_type = int.from_bytes(wps_ie[i:i+2], "big")
        field_length = int.from_bytes(wps_ie[i+2:i+4], "big")

        if field_type == 0x104A and field_length == 1:
            wps_version = wps_ie[i+4]
        elif field_type == 0x103C and field_length == 1:
            wps_2_0_flag = True
        i += 4 + field_length

    if wps_version is None:
        return None

    if wps_2_0_flag:
        return "2.0"

    return f"{wps_version >> 4}.{wps_version & 0xF}" if wps_version != 0x10 else "1.0"

# Поиск флага блокировки в probe-пакетах сети
def is_wps_locked(pkt: bytes) -> str:
	wps_locked_id = b'\x10\x57'
	wps_locked_id_probe = b'\0x01'
	index = pkt.find(wps_locked_id)
	
	if index != -1 and pkt[index +3] == 0x1:
		return 'Yes'
	return 'No'
	
def get_channel(pkt):
	channel = None
	if pkt.haslayer(Dot11Elt):
		elt = pkt.getlayer(Dot11Elt)
		while elt:
			if elt.ID == 3:
				channel = ord(elt.info)
				break
			elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
	return channel

def get_wps_ie(pkt):
	wps_ie = None
	elt = pkt.getlayer(Dot11Elt)
	while elt:
		if elt.ID == 221 and elt.info[:4] == b"\x00\x50\xF2\x04":  # WPS IE
			wps_ie = elt.info
			break
		elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
	return wps_ie
