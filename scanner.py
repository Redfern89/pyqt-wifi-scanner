#!/usr/bin/env python3

from PyQt5.QtWidgets import (
	QApplication, QTreeView, QVBoxLayout, QHBoxLayout, QWidget, QHeaderView, QPushButton, QLabel, QProgressBar, 
	QStyledItemDelegate, QStyleOptionProgressBar, QStyle, QComboBox, QSizePolicy, QMessageBox, QDialog, QTextEdit, QFileDialog,
	QMainWindow, QTableView, QStatusBar, QCheckBox
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QPainter, QPen, QPainterPath, QFont, QPixmap
from PyQt5.QtCore import Qt, QSize, QTimer, pyqtSignal, QObject, QMetaObject, Q_ARG, pyqtSlot, QItemSelection, QItemSelectionModel

import sys
import json
import csv
import re
import os
import time
import signal
import threading
import subprocess
import random
import contextlib

from scapy.all import *
from functools import partial

import checker
import wifi_manager
import dot11_utils

params = {
	'oui_path': 'data/oui.csv',
	'row_height': 40,
	'stations_row_height': 150
}

broadcast = 'ff:ff:ff:ff:ff:ff'

def scale_rssi(rssi_value, min_rssi=-90, max_rssi=-40, new_min=0, new_max=100):
    return max(new_min, min(new_max, (rssi_value - min_rssi) * (new_max - new_min) / (max_rssi - min_rssi) + new_min))

def load_oui_database(filename=params['oui_path']):
	oui_dict = {}
	
	if not os.path.exists(filename):
		print(f"Файл {filename} не найден")
		sys.exit(1)
	
	with open(filename, newline='', encoding='utf-8') as csvfile:
		reader = csv.reader(csvfile)
		for row in reader:
			if len(row) >= 3:
				oui = row[1].upper()
				vendor = row[2].strip()
				oui_dict[oui] = vendor
	return oui_dict

def get_vendor_from_mac(mac_address: str, oui_dict: dict) -> str:
	mac_prefix = mac_address.upper().replace(":", "").replace("-", "").replace(".", "")[:6]  # Приводим к формату 08EA44
	return oui_dict.get(mac_prefix, "Unknown")

oui_database = load_oui_database(params['oui_path'])

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
			#progress_option.setStyleSheet("QProgressBar {border: 2px solid grey; border-radius: 5px; text-align: center;}")
			progress_option.rect = bar_rect
			progress_option.minimum = 0
			progress_option.maximum = 100
			progress_option.progress = signal_strength
			progress_option.text = f"{rssi_value} dBm"
			progress_option.textVisible = True
			progress_option.textAlignment = Qt.AlignCenter

			painter.save()
			painter.setRenderHint(QPainter.Antialiasing)
			option.widget.style().drawControl(QStyle.CE_ProgressBar , progress_option, painter)
			#option.widget.style().drawControl(QStyle.CE_ProgressBar, progress_option, painter)
			painter.restore()
		else:
			super().paint(painter, option, index)

	def createEditor(self, parent, option, index):
		return None
		
class HexDumpDialog(QDialog):
	def __init__(self, hexdump_data, ssid, pkt, parent=None):
		super().__init__(parent)

		self.setWindowTitle(f"HexDump Data for \"{ssid}\"")
		self.setGeometry(200, 200, 700, 410)

		font = QFont("Courier")
		font.setStyleHint(QFont.TypeWriter)

		self.text_edit = QTextEdit(self)
		self.text_edit.setReadOnly(True)
		self.text_edit.setFont(font)
		self.text_edit.setPlainText(hexdump_data)

		self.btn_save = QPushButton('Сохранить в pcap-файл')
		self.btn_save.clicked.connect(self.save_pcap)
		
		self.pkt = pkt
		self.ssid = ssid
		
		top_layout = QHBoxLayout()
		top_layout.addWidget(self.btn_save)
		top_layout.setContentsMargins(5, 5, 5, 0)
		top_layout.addStretch()

		main_layout = QVBoxLayout()
		main_layout.addLayout(top_layout)
		main_layout.addWidget(self.text_edit)
		main_layout.setContentsMargins(0, 0, 0, 0)
		self.setLayout(main_layout)
		
	def save_pcap(self):
		options = QFileDialog.Options()
		file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить как", f"{self.ssid}.pcap", "PCAP Files (*.pcap)", options=options)
		
		if file_path:
			try:
				wrpcap(file_path, self.pkt)
			except Exception as e:
				print('Error')

class MyTableView(QTableView):
	def mousePressEvent(self, event):
		index = self.indexAt(event.pos())
		if not index.isValid():
			self.btn_refresh.setEnabled(False)
		else:
			super().mousePressEvent(event)
			self.btn_refresh.setEnabled(True)
		
class ChoseWiFiAdapderDialog(QDialog):
	def __init__(self, parent=None):
		super().__init__(parent)

		self.setWindowTitle("Выбор Wifi адаптера")
		self.setWindowIcon(QIcon('icons/ethernet.png'))
		self.setGeometry(200, 200, 1120, 520)

		self.table = QTableView(self)
		self.model = QStandardItemModel(0, 5, self)
		self.model.setHorizontalHeaderLabels(['PHY', 'Interface', 'MAC', 'Driver', 'Chipset', 'State', 'Mode'])

		self.table.setModel(self.model)
		self.table.horizontalHeader().setStretchLastSection(True)
		self.table.setEditTriggers(QTableView.NoEditTriggers)
		self.table.setShowGrid(False)
		self.table.verticalHeader().setVisible(False)
		self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.table.setIconSize(QSize(32, 32))
		self.table.selectionModel().selectionChanged.connect(self.on_selection_changed)
		self.table.doubleClicked.connect(self.select_iface)

		self.table.setColumnWidth(0, 90)
		self.table.setColumnWidth(1, 150)
		self.table.setColumnWidth(2, 150)
		self.table.setColumnWidth(4, 350)

		self.btn_refresh = QPushButton('Обновить')
		self.btn_updown = QPushButton('Поднять')
		self.btn_mode = QPushButton('Режим мониторинга')
		
		self.btn_refresh.setIcon(QIcon('icons/refresh.png'))
		self.btn_updown.setIcon(QIcon('icons/upward-arrow.png'))
		self.btn_mode.setIcon(QIcon('icons/connections.png'))
		
		self.btn_refresh.setIconSize(QSize(24, 24))
		self.btn_updown.setIconSize(QSize(24, 24))
		self.btn_mode.setIconSize(QSize(24, 24))
		
		self.btn_updown.setEnabled(False)
		self.btn_mode.setEnabled(False)
		
		self.btn_mode.clicked.connect(self.switch_iface_mode)
		self.btn_refresh.clicked.connect(self.update_list)
		self.btn_updown.clicked.connect(self.updown_iface)
		
		top_layout = QHBoxLayout()
		top_layout.addWidget(self.btn_refresh)
		top_layout.addWidget(self.btn_updown)
		top_layout.addWidget(self.btn_mode)
		top_layout.setContentsMargins(5, 5, 5, 0)
		top_layout.addStretch()

		main_layout = QVBoxLayout()
		main_layout.addLayout(top_layout)
		main_layout.addWidget(self.table)
		main_layout.setContentsMargins(0, 0, 0, 0)
		self.setLayout(main_layout)
		
		self.update_list()
	
	def select_iface(self):
		result = {}
		selected = self.table.selectionModel().currentIndex()
		phy = self.table.model().data(self.table.model().index(selected.row(), 0)).lower()
		iface = self.table.model().data(self.table.model().index(selected.row(), 1))

		if wifi_manager.iface_exists(iface) == False:
			QMessageBox.critical(self, "Error", f"Интерфейса {interface} не существует!")
			self.update_list()
			return
		
		result = {
			'interface': iface,
			'supported_channels': wifi_manager.get_phy_supported_channels(phy)
		}
		self.accept()

		return result
		
	def on_selection_changed(self, selected: QItemSelection, deselected: QItemSelection):
		indexes = selected.indexes()
		
		if indexes:
			row = indexes[0].row()
			self.btn_updown.setEnabled(True)
			self.btn_mode.setEnabled(True)
			
			mode = self.model.itemFromIndex(self.model.index(row, 6)).text()
			state = self.model.itemFromIndex(self.model.index(row, 5)).text()
			
			if mode == 'Monitor':
				self.btn_mode.setText('В режим станции')
				self.btn_mode.setIcon(QIcon('icons/global-network.png'))
			else:
				self.btn_mode.setText('В режим мониторинга')
				self.btn_mode.setIcon(QIcon('icons/connections.png'))

			if state == 'UP':
				self.btn_updown.setText('Отключить')
				self.btn_updown.setIcon(QIcon('icons/down-arrow.png'))
			else:
				self.btn_updown.setText('Поднять')
				self.btn_updown.setIcon(QIcon('icons/upward-arrow.png'))
		else:
			self.btn_updown.setEnabled(False)
			self.btn_mode.setEnabled(False)
		
	def update_list(self):
		self.model.setRowCount(0)
		phys = wifi_manager.handle_lost_phys()
		if phys is not None:
			for phy in phys:
				self.add_wifi_dev_item(phy)
	
	def add_wifi_dev_item(self, phy):
		PHYItem = QStandardItem(QIcon('icons/ethernet.png'), phy.upper())
		IFACEItem = QStandardItem(wifi_manager.iface_name_by_phy(phy))
		MACItem = QStandardItem(wifi_manager.get_phy_mac(phy).upper())
		DRIVERItem = QStandardItem(wifi_manager.get_phy_driver(phy))
		CHIPItem = QStandardItem(wifi_manager.get_phy_chipset(phy))
		STATEItem = QStandardItem('UP' if wifi_manager.get_phy_state(phy) else 'DOWN')
		IFACETYPEItem = QStandardItem(wifi_manager.get_phy_type(phy))
		
		row = [PHYItem, IFACEItem, MACItem, DRIVERItem, CHIPItem, STATEItem, IFACETYPEItem]
		
		self.model.appendRow(row)
		row_number = self.model.rowCount() -1
		self.table.setRowHeight(row_number, 40)
	
	def updown_iface(self):
		selected = self.table.selectionModel().currentIndex()
		phy = self.table.model().data(self.table.model().index(selected.row(), 0)).lower()
		iface = self.table.model().data(self.table.model().index(selected.row(), 1)).lower()
		state = self.table.model().data(self.table.model().index(selected.row(), 5))
		
		if state == 'UP':
			wifi_manager.set_phy_link(phy, 'down')
			time.sleep(1)
			if wifi_manager.get_phy_state(phy) != False:
				QMessageBox.critical(self, "Error", f"Не возможно отключить {iface}!")
		else:
			wifi_manager.set_phy_link(phy, 'up')
			time.sleep(1)
			if wifi_manager.get_phy_state(phy) != True:
				QMessageBox.critical(self, "Error", f"Не возможно включить {iface}!")
			
		self.update_list()
	
	def switch_iface_mode(self):
		selected = self.table.selectionModel().currentIndex()
		phy = self.table.model().data(self.table.model().index(selected.row(), 0)).lower()
		iface = self.table.model().data(self.table.model().index(selected.row(), 1)).lower()
		mode = self.table.model().data(self.table.model().index(selected.row(), 6)).lower()
		
		if mode == 'monitor':
			wifi_manager.set_phy_80211_station(phy)
			if wifi_manager.get_phy_type(phy) != 'Station':
				QMessageBox.critical(self, "Error", f"Не возможно переключить {iface} в режим станции!")
		else:
			wifi_manager.set_phy_80211_monitor(phy)
			if wifi_manager.get_phy_type(phy) != 'Monitor':
				QMessageBox.critical(self, "Error", f"Не возможно переключить {iface} в режим мониторинга!")		
		
		self.update_list()

class StationsTable(QWidget):
	def __init__(self, parent=None):
		super().__init__(parent)
		layout = QVBoxLayout(self)
		layout.setContentsMargins(35, 5, 5, 5)
		
		top_layout = QHBoxLayout()
		top_layout.setContentsMargins(0, 0, 0, 0)
		
		self.assocIconLabel = QLabel()
		self.assocIconLabel.setPixmap(QPixmap('icons/satellite-dish.png').scaled(24, 24, Qt.KeepAspectRatio))
		self.assocIconLabel.setFixedWidth(24)
		
		assocLabelFont = QFont()
		assocLabelFont.setBold(True)
		assocLabelFont.setPointSize(12)
		self.assocLabel = QLabel('Associated stations:')
		self.assocLabel.setFont(assocLabelFont)
		
		self.table = QTableView(self)
		self.model = QStandardItemModel(0, 5, self)
		self.model.setHorizontalHeaderLabels(['MAC', 'Vendor', 'RSSI', 'Frames', 'Rate', 'Modulation'])

		self.table.setModel(self.model)
		self.table.horizontalHeader().setStretchLastSection(True)
		self.table.setEditTriggers(QTableView.NoEditTriggers)
		self.table.setShowGrid(False)
		self.table.verticalHeader().setVisible(False)
		self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.table.setIconSize(QSize(32, 32))
		
		self.progress_delegate = ProgressBarDelegate(self.table)
		self.table.setItemDelegateForColumn(2, self.progress_delegate)

		self.table.setColumnWidth(0, 170)
		self.table.setColumnWidth(1, 220)
		self.table.setColumnWidth(2, 200)
		self.table.setColumnWidth(3, 55)
		self.table.setColumnWidth(4, 80)
		
		top_layout.addWidget(self.assocIconLabel)
		top_layout.addWidget(self.assocLabel)
		layout.addLayout(top_layout)
		layout.addWidget(self.table)
		self.setLayout(layout)

	def update_data(self, ssid, stations):
		self.model.setRowCount(0)
		
		self.assocLabel.setText(f'Associated stations for "{ssid}":')
		
		for station in stations:
			first_item = QStandardItem(QIcon('icons/signal.png'), str(station.get('station_MAC', "")))
			row = [first_item]
			for col in ['station_Vendor', 'station_dBm_AntSignal', 'station_Frames', 'station_Rate', 'station_ChannelFlags']:
				row.append(QStandardItem(str(station.get(col, ""))))
			self.model.appendRow(row)
			
			row_number = self.model.rowCount() -1
			self.table.setRowHeight(row_number, 40)
			

class MainWindow(QMainWindow):
	def __init__(self):
		super().__init__()
		
		self.networks = {}
		self.supported_channels = []
		self.interface = None
		
		self.statusbar = QStatusBar()
		self.setStatusBar(self.statusbar)
		
		self.statusLabel = QLabel('Interface not selected')
		
		self.interfaceIconLabel = QLabel()
		self.interfaceIconLabel.setPixmap(QPixmap('icons/ethernet.png').scaled(26, 26, Qt.KeepAspectRatio))
		
		self.networksIconLabel = QLabel()
		self.networksIconLabel.setPixmap(QPixmap('icons/menu.png').scaled(24, 24, Qt.KeepAspectRatio))
		
		self.timerIconLabel = QLabel()
		self.timerIconLabel.setPixmap(QPixmap('icons/clock-time.png').scaled(24, 24, Qt.KeepAspectRatio))
		
		self.netCountLabel = QLabel('Networks: 0')
		self.statusLabel.setFixedWidth(350)
		self.netCountLabel.setFixedWidth(250)
		self.workTimeLabel = QLabel('0d 00:00:00')

		self.statusbar.addWidget(self.interfaceIconLabel)
		self.statusbar.addWidget(self.statusLabel)
		self.statusbar.addWidget(self.networksIconLabel)
		self.statusbar.addWidget(self.netCountLabel)
		self.statusbar.addWidget(self.timerIconLabel)
		self.statusbar.addWidget(self.workTimeLabel)
		
		self.workTimer = QTimer()
		self.workTimer.setInterval(1000)
		self.workTimer.timeout.connect(self.on_work_timer)
				
		self.workSec = 0
		self.workMin = 0
		self.workHour = 0
		self.workDays = 0
		
		central_widget = QWidget()
		main_layout = QVBoxLayout()
		main_layout.setContentsMargins(0, 0, 0, 0)
		
		self.sniffing = False
		self.hopper_thread = None
		self.stop_hopping = threading.Event()
		
		self.setWindowTitle("PyQt WiFi scanner")
		self.setWindowIcon(QIcon('icons/satellite-dish.png'))
		self.setGeometry(100, 100, 1500, 530)
		
		self.btn_wifi = QPushButton('Выбор адаптера')
		self.btn_wifi.setIcon(QIcon('icons/ethernet.png'))
		self.btn_wifi.setIconSize(QSize(24, 24))
		self.btn_scan = QPushButton('Сканировать')
		self.btn_scan.setIcon(QIcon('icons/refresh.png'))
		self.btn_scan.setIconSize(QSize(24, 24))
		self.btn_stop = QPushButton('Остановить')
		self.btn_stop.setIcon(QIcon('icons/cancelled.png'))
		self.btn_stop.setIconSize(QSize(24, 24))
		
		self.btn_wifi.clicked.connect(self.chose_wifi_adapter_dialog)
		self.btn_scan.clicked.connect(self.scan_networks)
		self.btn_stop.clicked.connect(self.stop_scan)
		self.btn_scan.setEnabled(False)
		self.btn_stop.setEnabled(False)
		
		self.wps_checkbox = QCheckBox('Только WPS-сети')
		self.sta_checkbox = QCheckBox('Показывать подключенные станции')
		self.sta_checkbox.setChecked(Qt.Checked)
		
		top_layout = QHBoxLayout()
		top_layout.addWidget(self.btn_wifi)
		top_layout.addWidget(self.btn_scan)
		top_layout.addWidget(self.btn_stop)
		top_layout.addWidget(self.wps_checkbox)
		top_layout.addWidget(self.sta_checkbox)
		top_layout.setContentsMargins(5, 5, 5, 0)
		top_layout.addStretch()
		
		self.table = QTableView()
		main_layout.addLayout(top_layout)
		main_layout.addWidget(self.table)
		
		self.model = QStandardItemModel()
		header_labels = ["SSID", "BSSID", "Ch", "Enc", "Cipher", "AKM", "WPS", "Vendor", "Hardware", "Lck", "RSSI", "Beacons"]
		self.model.setHorizontalHeaderLabels(header_labels)
		self.table.setModel(self.model)
		
		self.table.setColumnWidth(0, 200)		# SSID
		self.table.setColumnWidth(1, 210)		# BSSID
		self.table.setColumnWidth(2, 50)		# CH
		self.table.setColumnWidth(3, 70)		# ENC
		self.table.setColumnWidth(4, 90)		# CIPHER
		self.table.setColumnWidth(5, 70)		# AKM
		self.table.setColumnWidth(6, 50)		# WPS
		self.table.setColumnWidth(7, 250)		# VENDOR
		self.table.setColumnWidth(8, 100)		# HARDWARE
		self.table.setColumnWidth(9, 50)		# LCK
		self.table.setColumnWidth(10, 280)		# RSSI
		self.table.setColumnWidth(11, 50)		# BEACONS

		self.table.setItemDelegateForColumn(10, ProgressBarDelegate(self.table))
		self.table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
		self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.table.horizontalHeader().setStretchLastSection(True)
		self.table.setIconSize(QSize(32, 32))
		self.table.setShowGrid(False)
		self.table.verticalHeader().setVisible(False)
		self.table.doubleClicked.connect(self.open_hexdump_window)
		self.previous_progress_values = {}
		#self.model.dataChanged.connect(self.on_update_table)

		self.setCentralWidget(central_widget)
		central_widget.setLayout(main_layout)
	
	def startWorkTimer(self):
		self.workTimeLabel.setText('0d 00:00:00')
		self.workTimer.start()
	
	def on_work_timer(self):
		self.workSec += 1
		if self.workSec > 59:
			self.workSec = 0
			self.workMin += 1
		elif self.workMin > 59:
			self.workMin = 0
			self.workHour += 1 
		elif self.workHour > 24:
			self.workSec = 0
			self.workMin = 0
			self.workHour = 0
			self.workDays += 1
		
		self.workTimeLabel.setText(f"{self.workDays}d {self.workHour:02d}:{self.workMin:02d}:{self.workSec:02d}")
	
	def chose_wifi_adapter_dialog(self):
		chose_wifi_dialog = ChoseWiFiAdapderDialog(self)
		chose_wifi_dialog.exec_()
		
		if chose_wifi_dialog.result() == QDialog.Accepted:
			result = chose_wifi_dialog.select_iface()
			if not result.get('interface') is None:
				self.interface = result.get('interface', None)
				self.supported_channels = result.get('supported_channels', None)
				self.statusLabel.setText(f"Interface: {self.interface}, CH: ?")
				self.btn_scan.setEnabled(True)
	
	def on_update_table(self, topLeft, bottomRight, roles):
		model = self.table.model()
		
		for row in range(topLeft.row(), bottomRight.row() +1):
			index = model.index(row, 7)
			item = self.model.item(row, 7)

			if not (topLeft.column() <= 8 <= bottomRight.column()):
				continue

			new_value = item.data(Qt.UserRole)
			old_value = self.previous_progress_values.get((row, 7), 0)
			
			if new_value is None or old_value is None:
				continue
				
			if new_value != old_value:
				self.timer = QTimer()
				self.timer.setInterval(5)
				self.timer.timeout.connect(lambda: self.update_progress(item, row, int(old_value), int(new_value)))
				self.timer.start()
				self.previous_progress_values[(row, 7)] = new_value
	
	def update_progress(self, item, row, old_value, new_value):
		if old_value < new_value:
			old_value += 1
			item.setText(str(old_value))
		elif old_value > new_value:
			old_value -= 1
			item.setText(str(old_value))
		else:
			self.timer.stop()
			self.timer.deleteLater()
	
	def get_hexdump(self, pkt):
		return hexdump(pkt, dump=True)

	def open_hexdump_window(self, index):
		item = self.model.itemFromIndex(index)
		bssid = self.model.itemFromIndex(self.model.index(index.row(), 1)).text()
		ssid = self.model.itemFromIndex(self.model.index(index.row(), 0)).text()
		network_info = self.networks.get(bssid.lower())
		
		if network_info:
			pkt = network_info.get('packet')
			if pkt:
				hexdump_data = self.get_hexdump(pkt)
				hexdump_dialog = HexDumpDialog(hexdump_data, ssid, pkt, self)
				hexdump_dialog.exec_()

	def stop_scan(self):
		self.btn_stop.setEnabled(False)
		self.sniffing = False
		self.stop_hopping.set()

		if self.hopper_thread:
			self.hopper_thread.join(timeout=1)
			self.hopper_thread = None
			self.sniff_thread.join()
			self.btn_scan.setEnabled(True)
			self.btn_wifi.setEnabled(True)
			self.wps_checkbox.setEnabled(True)
			self.workTimer.stop()
			self.statusLabel.setText(f"Interface: {self.interface}, CH: ?")

	def scan_networks(self):
		global interface
		if wifi_manager.get_iface_state(self.interface) == False:
			QMessageBox.critical(self, "Error", f"Интерфейс {interface} выключен!")
			return
			
		if wifi_manager.iface_exists(self.interface) == False:
			QMessageBox.critical(self, "Error", f"Интерфейса {interface} не существует!")
			return
		
		self.clear_list()
		self.btn_stop.setEnabled(True)
		self.btn_scan.setEnabled(False)
		self.btn_wifi.setEnabled(False)
		self.wps_checkbox.setEnabled(False)
		self.networks = {}

		if self.sniffing:
			return
		
		self.startWorkTimer()
		self.sniffing = True
		self.stop_hopping.clear()
		self.hopper_thread = threading.Thread(target=self.channel_hopper, daemon=True)
		self.hopper_thread.start()
		self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
		self.sniff_thread.start()
	
	def safe_chlabel_set_ch(self, ch):
		QMetaObject.invokeMethod(self, "__update_ch_label", Qt.QueuedConnection, Q_ARG(str, ch))
	
	@pyqtSlot(str)
	def __update_ch_label(self, ch):
		self.statusLabel.setText(f"Interface: {self.interface}, CH: {ch}")
	
	def channel_hopper(self):
		while not self.stop_hopping.is_set():  
			ch = random.choice(self.supported_channels)
			if self.stop_hopping.is_set():
				break
			wifi_manager.switch_iface_channel(self.interface, ch)
			self.safe_chlabel_set_ch(str(ch))
			time.sleep(0.2)

	def sniff_packets(self):
		while self.sniffing:
			sniff(iface=self.interface, prn=self.radio_packets_handler, store=0, timeout=5)

	def clear_list(self):
		while self.model.rowCount() > 0:
			self.model.removeRow(0)
	
	def safe_add_table_item(self, json_data):
		QMetaObject.invokeMethod(self, "__add_table_item", Qt.QueuedConnection, Q_ARG(str, json_data))
		
	@pyqtSlot(str)
	def __add_table_item(self, json_data):
		rows = []
		data = json.loads(json_data)
		for key, value in data.items():
			if key == 'ssid':
				item = QStandardItem(QIcon('icons/wifi-router.png'), value)
			else:
				item = QStandardItem(str(value))
			rows.append(item)
		
		self.model.appendRow(rows)
		row_number = self.model.rowCount() -1
		self.table.setRowHeight(row_number, int(params['row_height']))
		
		self.previous_progress_values[(row_number, 9)] = data['signal']
	
	def safe_update_item_by_bssid(self, bssid, item, data):
		QMetaObject.invokeMethod(self, "__update_item_by_bssid", Qt.QueuedConnection, Q_ARG(str, bssid), Q_ARG(int, item), Q_ARG(str, data))
	
	def safe_update_item_data_by_bssid(self, bssid, item, data):
		QMetaObject.invokeMethod(self, "__update_item_data_by_bssid", Qt.QueuedConnection, Q_ARG(str, bssid), Q_ARG(int, item), Q_ARG(str, data))
	
	@pyqtSlot(str, int, str)
	def __update_item_by_bssid(self, bssid, item, data):
		for row in range(self.model.rowCount()):
			item_bssid = self.model.item(row, 1)
			if item_bssid and item_bssid.text().upper() == bssid.upper():
				item = self.model.item(row, item) 
				if item:
					item.setText(str(data))
					item.setData(data, Qt.UserRole)
					
	@pyqtSlot(str, int, str)
	def __update_item_data_by_bssid(self, bssid, item, data):
		for row in range(self.model.rowCount()):
			item_bssid = self.model.item(row, 1)
			if item_bssid and item_bssid.text().upper() == bssid.upper():
				item = self.model.item(row, item) 
				if item:
					item.setData(data, Qt.UserRole)
	
	def safe_add_StationsList(self, bssid, stations_json):
		QMetaObject.invokeMethod(self, "__add_subitem", Qt.QueuedConnection, Q_ARG(str, bssid), Q_ARG(str, stations_json))
	
	def has_nested_exists(self, row):
		for col in range(self.model.columnCount()):
			index = self.model.index(row, col)
			widget = self.table.indexWidget(index)
			if isinstance(widget, QWidget):
				return True
		
		return False
		
	@pyqtSlot(str, str)
	def __add_subitem(self, bssid, stations_json):
		stations = json.loads(stations_json)
		for row in range(self.model.rowCount()):
			index = self.table.model().index(row, 0)
			ssid = self.table.model().data(index)
			
			if self.model.item(row, 1).text() == bssid:
				if self.has_nested_exists(row + 1):					
					subitem_index = self.model.index(row + 1, 0)
					stations_table = self.table.indexWidget(subitem_index)
					stations_table.update_data(ssid, stations)
					
					num_rows = stations_table.model.rowCount()
					new_height = max(75, ((num_rows * 40) + 64))
					self.table.setRowHeight(row +1, new_height)
				else:
					subitem = QStandardItem("")
					sub_row = [QStandardItem("") for _ in range(self.model.columnCount())]
					sub_row[0] = subitem
					self.model.insertRow(row + 1, sub_row)
					self.table.setSpan(row + 1, 0, 1, 8)
					subitem_index = self.model.index(row + 1, 0)
					stations_table = StationsTable(self)
					stations_table.update_data(ssid, stations)
					
					self.table.setIndexWidget(subitem_index, stations_table)
					self.table.setRowHeight(row +1, 103)
					
					self.table.viewport().update()
	
	def safe_update_networks_cnt(self, cnt):
		QMetaObject.invokeMethod(self, "__update_networks_cnt", Qt.QueuedConnection, Q_ARG(int, cnt))
	
	@pyqtSlot(int)
	def __update_networks_cnt(self, cnt):
		self.netCountLabel.setText(f"Networks: {cnt}")
	
	def stations_handler(self, pkt):
		ap_mac = pkt.addr2
		if ((ap_mac in self.networks) and (pkt.type == 1 and pkt.subtype in [8, 9])):
			if pkt.addr1 != broadcast:

				station_MAC = pkt.addr1
				station_dBm_AntSignal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
				station_ChannelFlags = pkt.ChannelFlags if hasattr(pkt, 'ChannelFlags') else '?'
				station_Rate = pkt.Rate if hasattr(pkt, 'Rate') else '?'
				station_Rate = '?' if station_Rate is None else station_Rate
				station_Vendor = get_vendor_from_mac(station_MAC, oui_database)
				
				if ap_mac in self.networks:
					stations_networks = self.networks[ap_mac]['stations']

					if station_MAC in stations_networks:
						self.networks[ap_mac]['stations'][station_MAC]['station_Frames'] += 1
						self.networks[ap_mac]['stations'][station_MAC]['station_dBm_AntSignal'] = station_dBm_AntSignal
						self.networks[ap_mac]['stations'][station_MAC]['station_ChannelFlags'] = str(station_ChannelFlags)
						self.networks[ap_mac]['stations'][station_MAC]['station_Rate'] = f"{station_Rate} mB/s"
					else:
						self.networks[ap_mac]['stations'][station_MAC] = {
							'station_MAC': station_MAC,
							'station_Vendor': station_Vendor,
							'station_dBm_AntSignal': station_dBm_AntSignal,
							'station_ChannelFlags': str(station_ChannelFlags),
							'station_Rate': f"{station_Rate} mB/s",
							'station_Frames': 1
						}

					stations_dict = list(self.networks[ap_mac]['stations'].values())
					stations_json = json.dumps(stations_dict, default=str)
					self.safe_add_StationsList(ap_mac, stations_json);		
	
	def radio_packets_handler(self, pkt):
		if self.sta_checkbox.isChecked():
			self.stations_handler(pkt)
		
		if not pkt.haslayer(Dot11Beacon):
			return
		
		bssid = pkt.addr3
		ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else None
		signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else None
		channel = dot11_utils.get_channel(pkt)
		
		if ((ssid is None) or (ssid == '')):
			return
			
		if channel is None:
			return
		
		wps_version = '-'
		wps_locked = '-'

		wps_ie = dot11_utils.get_wps_ie(pkt)
		
		if self.wps_checkbox.isChecked() and not wps_ie:
			return
		
		if not bssid in self.networks:
			enc_info = dot11_utils.get_wifi_akm_info(pkt)
			ciphers = ','.join(enc_info['ciphers'])
			akms = ','.join(enc_info['akms'])
			
			vendor = get_vendor_from_mac(bssid, oui_database)
			chip = dot11_utils.get_chip_vendor(bytes(pkt))
			
			if wps_ie:
				wps_version = dot11_utils.parse_wps_version(wps_ie)
				wps_locked = dot11_utils.is_wps_locked(bytes(pkt))
				if wps_version is None:
					return

			self.networks[bssid] = {
				'ssid': ssid,
				'bssid': bssid,
				'channel': channel,
				'enc': dot11_utils.get_wifi_encryption(pkt),
				'cipher': ciphers,
				'akm': akms,
				'wps_version': wps_version,
				'vendor': vendor,
				'chip': chip,
				'locked': wps_locked,
				'signal': int(signal),
				'beacons': 1,
				'packet': pkt,
				'stations': {}
			}
			
			self.safe_update_networks_cnt(len(self.networks))

			json_data = json.dumps({k: v for k, v in self.networks[bssid].items() if k not in ['packet', 'stations']})
			self.safe_add_table_item(json_data)
		else:
			self.networks[bssid]['channel'] = channel
			self.networks[bssid]['signal'] = signal
			self.networks[bssid]['beacons'] +=1
			self.networks[bssid]['packet'] = pkt
			beacons = self.networks[bssid]['beacons']
			
			self.safe_update_item_by_bssid(bssid, 2, str(channel))
			self.safe_update_item_by_bssid(bssid, 10, str(signal))
			self.safe_update_item_by_bssid(bssid, 11, str(beacons))			

if __name__ == '__main__':
	if checker.check_all_need():
		app = QApplication(sys.argv)
		window = MainWindow()
		window.show()
		sys.exit(app.exec_())
