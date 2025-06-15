import sys
import platform
import socket
import uuid
import psutil
import bcrypt
import mysql.connector
from mysql.connector import Error
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
                             QVBoxLayout, QHBoxLayout, QMessageBox, QTableWidget, QTableWidgetItem,
                             QComboBox, QTextEdit, QDateEdit)
from PyQt5.QtCore import QDate

DB_HOST = "lochnagar.abertay.ac.uk"
DB_USER = "sql2000112"
DB_PASSWORD = "HNrxPQcepV96"
DB_NAME = "sql2000112"

class AssetTrackerDB:
    def __init__(self):
        self.conn = self.create_connection()

    def create_connection(self):
        try:
            connection = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )
            if connection.is_connected():
                print("Connected to MySQL database successfully.")
                return connection
        except Error as e:
            print(f"Error while connecting to MySQL: {e}")
            return None

    def add_user(self, email, password, department):
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO ats_users (email, password, department) VALUES (%s, %s, %s)",
                      (email, hashed_pw, department))
        self.conn.commit()

    def verify_user(self, email, password):
        cursor = self.conn.cursor()
        cursor.execute("SELECT password, department FROM ats_users WHERE email=%s", (email,))
        row = cursor.fetchone()
        if row and bcrypt.checkpw(password.encode(), row[0].encode()):
            return row[1]
        return None

    def add_hardware_asset(self, info, purchase_date, note):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO hardware_assets (system_name, model, manufacturer, asset_type, ip_address, purchase_date, note)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            info['system_name'],
            info['model'],
            info['manufacturer'],
            info['asset_type'],
            info['ip_address'],
            purchase_date,
            note
        ))
        self.conn.commit()


def get_hardware_info():
    return {
        "system_name": platform.node(),
        "model": platform.machine(),
        "manufacturer": platform.system(),
        "asset_type": "PC",
        "ip_address": socket.gethostbyname(socket.gethostname())
    }

def get_software_info():
    return {
        "os_name": platform.system(),
        "version": platform.version(),
        "manufacturer": platform.platform()
    }

class LoginWindow(QWidget):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.setWindowTitle("Login")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.email_input = QLineEdit(self)
        self.email_input.setPlaceholderText("Email")
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        login_btn = QPushButton("Login", self)
        login_btn.clicked.connect(self.login)
        layout.addWidget(self.email_input)
        layout.addWidget(self.password_input)
        layout.addWidget(login_btn)
        self.setLayout(layout)

    def login(self):
        email = self.email_input.text()
        password = self.password_input.text()
        department = self.db.verify_user(email, password)
        if department:
            self.main_window = MainWindow(self.db, email, department)
            self.main_window.show()
            self.close()
        else:
            QMessageBox.warning(self, "Error", "Invalid credentials")

class MainWindow(QMainWindow):
    def __init__(self, db, user_email, department):
        super().__init__()
        self.db = db
        self.user_email = user_email
        self.department = department
        self.setWindowTitle(f"Asset Tracker - {user_email} ({department})")
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        layout = QVBoxLayout()
        hw_btn = QPushButton("Capture Hardware Info")
        sw_btn = QPushButton("Capture Software Info")
        add_hw_btn = QPushButton("Add Hardware Asset")
        hw_btn.clicked.connect(self.capture_hw)
        sw_btn.clicked.connect(self.capture_sw)
        add_hw_btn.clicked.connect(self.open_add_hardware_form)
        layout.addWidget(hw_btn)
        layout.addWidget(sw_btn)
        layout.addWidget(add_hw_btn)
        central.setLayout(layout)
        self.setCentralWidget(central)

    def capture_hw(self):
        info = get_hardware_info()
        QMessageBox.information(self, "Hardware Info", str(info))

    def capture_sw(self):
        info = get_software_info()
        QMessageBox.information(self, "Software Info", str(info))

    def open_add_hardware_form(self):
        self.hw_form = AddHardwareAssetForm(self.db)
        self.hw_form.show()

class AddHardwareAssetForm(QWidget):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.setWindowTitle("Add Hardware Asset")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.info = get_hardware_info()

        self.purchase_input = QDateEdit(calendarPopup=True)
        self.purchase_input.setDate(QDate.currentDate())
        self.note_input = QTextEdit()

        save_btn = QPushButton("Save Asset")
        save_btn.clicked.connect(self.save_asset)

        layout.addWidget(QLabel(f"System Name: {self.info['system_name']}"))
        layout.addWidget(QLabel(f"Model: {self.info['model']}"))
        layout.addWidget(QLabel(f"Manufacturer: {self.info['manufacturer']}"))
        layout.addWidget(QLabel(f"IP Address: {self.info['ip_address']}"))
        layout.addWidget(QLabel("Purchase Date:"))
        layout.addWidget(self.purchase_input)
        layout.addWidget(QLabel("Note:"))
        layout.addWidget(self.note_input)
        layout.addWidget(save_btn)
        self.setLayout(layout)

    def save_asset(self):
        purchase_date = self.purchase_input.date().toPyDate()
        note = self.note_input.toPlainText()
        self.db.add_hardware_asset(self.info, purchase_date, note)
        QMessageBox.information(self, "Saved", "Hardware asset added successfully!")
        self.close()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    db = AssetTrackerDB()
    login = LoginWindow(db)
    login.show()
    sys.exit(app.exec_())
