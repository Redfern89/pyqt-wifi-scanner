#!/usr/bin/env python3

import sys
from PyQt5.QtWidgets import QApplication, QDialog, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout
from PyQt5.QtGui import QFont

class SettingsDialog(QDialog):
	def __init__(self, parent=None):
		super().__init__(parent)

		self.setWindowTitle("Настрйоки")
		self.setGeometry(200, 200, 700, 410)
				
		top_layout = QHBoxLayout()
		main_layout = QVBoxLayout()
		main_layout.addLayout(top_layout)

		self.setLayout(main_layout)

if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = SettingsDialog()
	window.show()
	sys.exit(app.exec_())
