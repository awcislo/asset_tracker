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
                             QComboBox, QTextEdit, QDateEdit, QInputDialog)

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

    def add_employee(self, first_name, last_name, email):
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO employees (first_name, last_name, email) VALUES (%s, %s, %s)",
                       (first_name, last_name, email))
        self.conn.commit()

    def get_employees(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, first_name, last_name FROM employees")
        return cursor.fetchall()

    def add_hardware_asset(self, info, purchase_date, note, employee_id):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO hardware_assets (system_name, model, manufacturer, asset_type, ip_address, purchase_date, note, employee_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            info['system_name'],
            info['model'],
            info['manufacturer'],
            info['asset_type'],
            info['ip_address'],
            purchase_date,
            note,
            employee_id
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
class AddEmployeeForm(QWidget):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.setWindowTitle("Manage Employees")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.first_input = QLineEdit()
        self.first_input.setPlaceholderText("First Name")
        self.last_input = QLineEdit()
        self.last_input.setPlaceholderText("Last Name")
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email")
        add_btn = QPushButton("Add Employee")
        add_btn.clicked.connect(self.save_employee)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["ID", "Name", "Email"])
        self.load_employees()

        layout.addWidget(QLabel("First Name:"))
        layout.addWidget(self.first_input)
        layout.addWidget(QLabel("Last Name:"))
        layout.addWidget(self.last_input)
        layout.addWidget(QLabel("Email:"))
        layout.addWidget(self.email_input)
        layout.addWidget(add_btn)
        layout.addWidget(QLabel("Existing Employees:"))
        layout.addWidget(self.table)
        self.setLayout(layout)

    def save_employee(self):
        fn = self.first_input.text()
        ln = self.last_input.text()
        email = self.email_input.text()
        if fn and ln and email:
            self.db.add_employee(fn, ln, email)
            QMessageBox.information(self, "Success", "Employee added!")
            self.first_input.clear()
            self.last_input.clear()
            self.email_input.clear()
            self.load_employees()
        else:
            QMessageBox.warning(self, "Missing Info", "Please fill all fields.")

    def load_employees(self):
        employees = self.db.get_employees()
        self.table.setRowCount(len(employees))
        for row_idx, (emp_id, fname, lname) in enumerate(employees):
            self.table.setItem(row_idx, 0, QTableWidgetItem(str(emp_id)))
            self.table.setItem(row_idx, 1, QTableWidgetItem(f"{fname} {lname}"))
            self.table.setItem(row_idx, 2, QTableWidgetItem(""))

            delete_btn = QPushButton("Delete")
            delete_btn.clicked.connect(lambda _, eid=emp_id: self.delete_employee(eid))
            self.table.setCellWidget(row_idx, 2, delete_btn)

    def delete_employee(self, emp_id):
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM hardware_assets WHERE employee_id = %s", (emp_id,))
        count = cursor.fetchone()[0]
        if count > 0:
            QMessageBox.warning(self, "Cannot Delete", f"Employee ID {emp_id} is linked to existing assets.")
            return

        confirm = QMessageBox.question(self, "Confirm", f"Delete employee ID {emp_id}?", QMessageBox.Yes | QMessageBox.No)
        if confirm == QMessageBox.Yes:
            cursor.execute("DELETE FROM employees WHERE id = %s", (emp_id,))
            self.db.conn.commit()
            self.load_employees()

    def mouseDoubleClickEvent(self, event):
        row = self.table.currentRow()
        if row >= 0:
            emp_id = self.table.item(row, 0).text()
            fname, lname = self.table.item(row, 1).text().split()
            email, ok = QInputDialog.getText(self, "Edit Email", "New Email:")
            if ok:
                cursor = self.db.conn.cursor()
                cursor.execute("UPDATE employees SET email=%s WHERE id=%s", (email, emp_id))
                self.db.conn.commit()
                self.load_employees()

    def contextMenuEvent(self, event):
        row = self.table.currentRow()
        if row >= 0:
            emp_id = self.table.item(row, 0).text()
            cursor = self.db.conn.cursor()
            cursor.execute("SELECT * FROM hardware_assets WHERE employee_id=%s", (emp_id,))
            assets = cursor.fetchall()
            if assets:
                msg = "\n\n".join([f"{a[0]}: {a[1]} ({a[5]})" for a in assets])
                QMessageBox.information(self, "Assigned Assets", msg)
            else:
                QMessageBox.information(self, "Assigned Assets", "No hardware assets found for this employee.")


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
        emp_btn = QPushButton("Manage Employees")
        hw_btn.clicked.connect(self.capture_hw)
        sw_btn.clicked.connect(self.capture_sw)
        add_hw_btn.clicked.connect(self.open_add_hardware_form)
        emp_btn.clicked.connect(self.open_employee_form)
        layout.addWidget(hw_btn)
        layout.addWidget(sw_btn)
        layout.addWidget(add_hw_btn)
        layout.addWidget(emp_btn)
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
        
    def open_employee_form(self):
        self.emp_form = AddEmployeeForm(self.db)
        self.emp_form.show()


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
        self.employee_dropdown = QComboBox()

        employees = self.db.get_employees()
        self.employee_map = {}
        for emp_id, fname, lname in employees:
            label = f"{fname} {lname}"
            self.employee_dropdown.addItem(label)
            self.employee_map[label] = emp_id

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
        layout.addWidget(QLabel("Assign to Employee:"))
        layout.addWidget(self.employee_dropdown)
        layout.addWidget(save_btn)
        self.setLayout(layout)

    def save_asset(self):
        purchase_date = self.purchase_input.date().toPyDate()
        note = self.note_input.toPlainText()
        employee_name = self.employee_dropdown.currentText()
        employee_id = self.employee_map.get(employee_name)
        self.db.add_hardware_asset(self.info, purchase_date, note, employee_id)
        QMessageBox.information(self, "Saved", "Hardware asset added successfully!")
        self.close()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    db = AssetTrackerDB()
    login = LoginWindow(db)
    login.show()
    sys.exit(app.exec_())


