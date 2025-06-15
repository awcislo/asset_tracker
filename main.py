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
        import mysql.connector
        from mysql.connector import Error
        try:
            return mysql.connector.connect(
                host="lochnagar.abertay.ac.uk",
                user="sql2000112",
                password="HNrxPQcepV96",
                database="sql2000112"
            )
        except Error as e:
            print("Connection error:", e)
            return None

    def verify_user(self, email, password):
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, password, department FROM employees WHERE email=%s", (email,))
        row = cursor.fetchone()
        if row and bcrypt.checkpw(password.encode(), row[1].encode()):
            return row[0], row[2]  # user_id and department
        return None, None

    def add_employee(self, first_name, last_name, email, password, department):
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO employees (first_name, last_name, email, password, department) VALUES (%s, %s, %s, %s, %s)",
                       (first_name, last_name, email, hashed_pw.decode(), department))
        self.conn.commit()

    def get_employees(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, first_name, last_name, email, department FROM employees")
        return cursor.fetchall()

    def get_assets_for_employee(self, emp_id):
        cursor = self.conn.cursor()
        cursor.execute("SELECT system_name, model, manufacturer FROM hardware_assets WHERE employee_id=%s", (emp_id,))
        return cursor.fetchall()

    def get_software_for_employee(self, emp_id):
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT sa.os_name, sa.version FROM software_assets sa
            JOIN asset_links al ON sa.id = al.software_id
            JOIN hardware_assets ha ON ha.id = al.hardware_id
            WHERE ha.employee_id = %s
        """, (emp_id,))
        return cursor.fetchall()
    def add_hardware_asset(self, sysname, model, manufacturer, asset_type, ip_address, purchase_date, note, employee_id):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO hardware_assets (system_name, model, manufacturer, asset_type, ip_address, purchase_date, note, employee_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (sysname, model, manufacturer, asset_type, ip_address, purchase_date, note, employee_id))
        self.conn.commit()

class AddEmployeeForm(QWidget):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.setWindowTitle("Register New Employee")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.first_input = QLineEdit()
        self.first_input.setPlaceholderText("First Name")
        self.last_input = QLineEdit()
        self.last_input.setPlaceholderText("Last Name")
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email")
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Password")
        self.pass_input.setEchoMode(QLineEdit.Password)

        self.dept_select = QComboBox()
        self.dept_select.addItems(["information technology", "sales", "finance", "operations", "human resources"])

        save_btn = QPushButton("Create Account")
        save_btn.clicked.connect(self.save_employee)

        layout.addWidget(QLabel("First Name:"))
        layout.addWidget(self.first_input)
        layout.addWidget(QLabel("Last Name:"))
        layout.addWidget(self.last_input)
        layout.addWidget(QLabel("Email:"))
        layout.addWidget(self.email_input)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.pass_input)
        layout.addWidget(QLabel("Department:"))
        layout.addWidget(self.dept_select)
        layout.addWidget(save_btn)

        self.setLayout(layout)

    def save_employee(self):
        fn = self.first_input.text().strip()
        ln = self.last_input.text().strip()
        email = self.email_input.text().strip()
        pwd = self.pass_input.text().strip()
        dept = self.dept_select.currentText()

        if not all([fn, ln, email, pwd]):
            QMessageBox.warning(self, "Incomplete", "Please complete all fields.")
            return

        self.db.add_employee(fn, ln, email, pwd, dept)
        QMessageBox.information(self, "Success", f"Employee '{fn} {ln}' added.")
        self.close()
class AddHardwareAssetForm(QWidget):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.setWindowTitle("Add Hardware Asset")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.sysname = platform.node()
        self.model = platform.machine()
        self.manufacturer = platform.system()
        self.asset_type = "PC"
        self.ip_address = socket.gethostbyname(socket.gethostname())

        self.date_input = QDateEdit(calendarPopup=True)
        self.date_input.setDate(datetime.today())
        self.note_input = QTextEdit()

        self.employee_dropdown = QComboBox()
        self.employee_map = {}
        for emp_id, fname, lname, _, _ in self.db.get_employees():
            label = f"{fname} {lname}"
            self.employee_dropdown.addItem(label)
            self.employee_map[label] = emp_id

        save_btn = QPushButton("Save Asset")
        save_btn.clicked.connect(self.save_asset)

        layout.addWidget(QLabel(f"System Name: {self.sysname}"))
        layout.addWidget(QLabel(f"Model: {self.model}"))
        layout.addWidget(QLabel(f"Manufacturer: {self.manufacturer}"))
        layout.addWidget(QLabel(f"IP Address: {self.ip_address}"))
        layout.addWidget(QLabel("Purchase Date:"))
        layout.addWidget(self.date_input)
        layout.addWidget(QLabel("Note:"))
        layout.addWidget(self.note_input)
        layout.addWidget(QLabel("Assign to Employee:"))
        layout.addWidget(self.employee_dropdown)
        layout.addWidget(save_btn)

        self.setLayout(layout)

    def save_asset(self):
        employee_name = self.employee_dropdown.currentText()
        employee_id = self.employee_map.get(employee_name)
        self.db.add_hardware_asset(
            self.sysname,
            self.model,
            self.manufacturer,
            self.asset_type,
            self.ip_address,
            self.date_input.date().toPyDate(),
            self.note_input.toPlainText(),
            employee_id
        )
        QMessageBox.information(self, "Success", "Hardware asset recorded.")
        self.close()
        
class EmployeeMonitor(QWidget):
    def __init__(self, db, department):
        super().__init__()
        self.db = db
        self.department = department
        self.setWindowTitle("Employee Monitor")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["ID", "Name", "Email", "Department", "Hardware Assets", "Software Assets"])

        employees = self.db.get_employees()
        self.table.setRowCount(len(employees))

        for i, (emp_id, fname, lname, email, dept) in enumerate(employees):
            full_name = f"{fname} {lname}"
            hw_assets = self.db.get_assets_for_employee(emp_id)
            sw_assets = self.db.get_software_for_employee(emp_id)
            hw_info = "; ".join([f"{a[0]} - {a[1]}" for a in hw_assets]) if hw_assets else "None"
            sw_info = "; ".join([f"{a[0]} {a[1]}" for a in sw_assets]) if sw_assets else "None"

            self.table.setItem(i, 0, QTableWidgetItem(str(emp_id)))
            self.table.setItem(i, 1, QTableWidgetItem(full_name))
            self.table.setItem(i, 2, QTableWidgetItem(email))
            self.table.setItem(i, 3, QTableWidgetItem(dept))
            self.table.setItem(i, 4, QTableWidgetItem(hw_info))
            self.table.setItem(i, 5, QTableWidgetItem(sw_info))

        layout.addWidget(self.table)

        if self.department.lower() == "information technology":
            self.add_btn = QPushButton("Add Employee")
            self.add_btn.clicked.connect(self.open_add_employee_form)
            self.hw_btn = QPushButton("Add Hardware to Employee")
            self.hw_btn.clicked.connect(self.open_add_hardware_form)
            layout.addWidget(self.add_btn)
            layout.addWidget(self.hw_btn)

        self.setLayout(layout)

    def open_add_employee_form(self):
        self.add_form = AddEmployeeForm(self.db)
        self.add_form.show()
          
    def open_add_hardware_form(self):
        self.hw_form = AddHardwareAssetForm(self.db)
        self.hw_form.show()

class MainWindow(QMainWindow):
    def __init__(self, db, user_id, department):
        super().__init__()
        self.db = db
        self.user_id = user_id
        self.department = department
        self.setWindowTitle("Asset Tracker Dashboard")
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        layout = QVBoxLayout()

        hw_btn = QPushButton("Capture Hardware Info")
        sw_btn = QPushButton("Capture Software Info")
        add_hw_btn = QPushButton("Add Hardware Asset")

        layout.addWidget(hw_btn)
        layout.addWidget(sw_btn)
        layout.addWidget(add_hw_btn)

        hw_btn.clicked.connect(lambda: QMessageBox.information(self, "Hardware Info", str(get_hardware_info())))
        sw_btn.clicked.connect(lambda: QMessageBox.information(self, "Software Info", str(get_software_info())))
        add_hw_btn.clicked.connect(lambda: QMessageBox.information(self, "Add Asset", "This would open the asset form"))

        if self.department.lower() == "information technology":
            emp_btn = QPushButton("Open Employee Monitor")
            emp_btn.clicked.connect(self.open_monitor)
            layout.addWidget(emp_btn)

        central.setLayout(layout)
        self.setCentralWidget(central)

    def open_monitor(self):
        self.monitor = EmployeeMonitor(self.db, self.department)
        self.monitor.show()

class LoginWindow(QWidget):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.setWindowTitle("Login")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        login_btn = QPushButton("Login")
        login_btn.clicked.connect(self.login)

        layout.addWidget(self.email_input)
        layout.addWidget(self.password_input)
        layout.addWidget(login_btn)
        self.setLayout(layout)

    def login(self):
        email = self.email_input.text()
        password = self.password_input.text()
        user_id, department = self.db.verify_user(email, password)
        if department:
            self.window = MainWindow(self.db, user_id, department)
            self.window.show()
            self.close()
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid email or password.")

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

if __name__ == '__main__':
    app = QApplication(sys.argv)
    db = AssetTrackerDB()

    login = LoginWindow(db)
    login.show()

    sys.exit(app.exec_())



