import sys
import platform
import socket
import bcrypt
import mysql.connector
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QMessageBox, QTableWidget, QTableWidgetItem, QComboBox,
    QTextEdit, QDateEdit, QHBoxLayout
)

DB_HOST = "lochnagar.abertay.ac.uk"
DB_USER = "sql2000112"
DB_PASSWORD = "HNrxPQcepV96"
DB_NAME = "sql2000112"

class AssetTrackerDB:
    def __init__(self):
        self.conn = self.create_connection()

    def create_connection(self):
        try:
            return mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )
        except mysql.connector.Error as e:
            print("Connection error:", e)
            return None

    def verify_user(self, email, password):
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, password, department FROM employees WHERE email=%s", (email,))
        row = cursor.fetchone()
        if row and bcrypt.checkpw(password.encode(), row[1].encode()):
            return row[0], row[2]
        return None, None

    def add_employee(self, first_name, last_name, email, password, department):
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO employees (first_name, last_name, email, password, department) VALUES (%s, %s, %s, %s, %s)",
            (first_name, last_name, email, hashed_pw.decode(), department)
        )
        self.conn.commit()

    def get_employees(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, first_name, last_name, email, department FROM employees")
        return cursor.fetchall()

    def get_assets_for_employee(self, emp_id):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT system_name, model, manufacturer FROM hardware_assets WHERE employee_id=%s",
            (emp_id,))
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

    def get_software_assets(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, os_name, version, manufacturer FROM software_assets")
        return cursor.fetchall()

    def add_software_asset(self, os_name, version, manufacturer):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO software_assets (os_name, version, manufacturer) VALUES (%s, %s, %s)",
            (os_name, version, manufacturer)
        )
        self.conn.commit()
        return cursor.lastrowid

    def update_software_asset(self, asset_id, os_name, version, manufacturer):
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE software_assets SET os_name=%s, version=%s, manufacturer=%s WHERE id=%s",
            (os_name, version, manufacturer, asset_id)
        )
        self.conn.commit()

    def delete_software_asset(self, asset_id):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM asset_links WHERE software_id=%s", (asset_id,))
        cursor.execute("DELETE FROM software_assets WHERE id=%s", (asset_id,))
        self.conn.commit()

    def get_all_hardware(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, system_name, model FROM hardware_assets")
        return cursor.fetchall()

    def get_hardware_for_software(self, software_id):
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT ha.id, ha.system_name, ha.model
            FROM hardware_assets ha
            JOIN asset_links al ON ha.id = al.hardware_id
            WHERE al.software_id = %s
        """, (software_id,))
        return cursor.fetchall()

    def link_software_to_hardware(self, software_id, hardware_id):
        cursor = self.conn.cursor()
        # Remove existing links
        cursor.execute("DELETE FROM asset_links WHERE software_id=%s", (software_id,))
        cursor.execute("INSERT INTO asset_links (hardware_id, software_id, link_date) VALUES (%s, %s, NOW())", (hardware_id, software_id))
        self.conn.commit()
# Employees CRUD (added delete, update)
    def update_employee(self, emp_id, fname, lname, email):
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE employees SET first_name=%s, last_name=%s, email=%s WHERE id=%s",
            (fname, lname, email, emp_id))
        self.conn.commit()

    def can_delete_employee(self, emp_id):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM hardware_assets WHERE employee_id=%s", (emp_id,))
        return cursor.fetchone()[0] == 0

    def delete_employee(self, emp_id):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM employees WHERE id=%s", (emp_id,))
        self.conn.commit()

    # Hardware CRUD
    def get_hardware_assets(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, system_name, model, manufacturer, asset_type, ip_address, purchase_date, note, employee_id
            FROM hardware_assets
        """)
        return cursor.fetchall()

    def update_hardware_asset(self, hw_id, sysname, model, manufacturer, asset_type, ip_address, purchase_date, note, employee_id):
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE hardware_assets
            SET system_name=%s, model=%s, manufacturer=%s, asset_type=%s, ip_address=%s, purchase_date=%s, note=%s, employee_id=%s
            WHERE id=%s
        """, (sysname, model, manufacturer, asset_type, ip_address, purchase_date, note, employee_id, hw_id))
        self.conn.commit()

    def can_delete_hardware(self, hw_id):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM asset_links WHERE hardware_id=%s", (hw_id,))
        return cursor.fetchone()[0] == 0

    def delete_hardware_asset(self, hw_id):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM hardware_assets WHERE id=%s", (hw_id,))
        self.conn.commit()

class AddSoftwareAssetForm(QWidget):
    def __init__(self, db, edit_asset=None, refresh_callback=None):
        super().__init__()
        self.db = db
        self.edit_asset = edit_asset
        self.refresh_callback = refresh_callback
        self.setWindowTitle("Edit Software Asset" if edit_asset else "Add Software Asset")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.os_name_input = QLineEdit()
        self.os_name_input.setPlaceholderText("OS Name (e.g. Windows 10)")
        self.version_input = QLineEdit()
        self.version_input.setPlaceholderText("Version (e.g. 21H2)")
        self.manufacturer_input = QLineEdit()
        self.manufacturer_input.setPlaceholderText("Manufacturer (e.g. Microsoft)")

        # Hardware dropdown
        self.hardware_dropdown = QComboBox()
        self.hardware_map = {}
        for hw_id, sys_name, model in self.db.get_all_hardware():
            label = f"{sys_name} ({model})"
            self.hardware_dropdown.addItem(label)
            self.hardware_map[label] = hw_id

        if self.edit_asset:
            sw_id, os_name, version, manufacturer = self.edit_asset
            self.os_name_input.setText(os_name)
            self.version_input.setText(version)
            self.manufacturer_input.setText(manufacturer)
            # Set dropdown to currently linked hardware if exists
            linked_hw = self.db.get_hardware_for_software(sw_id)
            if linked_hw:
                linked_label = f"{linked_hw[0][1]} ({linked_hw[0][2]})"
                self.hardware_dropdown.setCurrentText(linked_label)

        save_btn = QPushButton("Update Software Asset" if self.edit_asset else "Save Software Asset")
        save_btn.clicked.connect(self.save_asset)
        layout.addWidget(QLabel("OS Name:"))
        layout.addWidget(self.os_name_input)
        layout.addWidget(QLabel("Version:"))
        layout.addWidget(self.version_input)
        layout.addWidget(QLabel("Manufacturer:"))
        layout.addWidget(self.manufacturer_input)
        layout.addWidget(QLabel("Link to Hardware:"))
        layout.addWidget(self.hardware_dropdown)
        layout.addWidget(save_btn)
        self.setLayout(layout)

    def save_asset(self):
        os_name = self.os_name_input.text().strip()
        version = self.version_input.text().strip()
        manufacturer = self.manufacturer_input.text().strip()
        hardware_label = self.hardware_dropdown.currentText()
        hardware_id = self.hardware_map.get(hardware_label)

        if not all([os_name, version, manufacturer, hardware_id]):
            QMessageBox.warning(self, "Incomplete", "Please fill all fields and select hardware.")
            return

        if self.edit_asset:
            sw_id = self.edit_asset[0]
            self.db.update_software_asset(sw_id, os_name, version, manufacturer)
            self.db.link_software_to_hardware(sw_id, hardware_id)
            QMessageBox.information(self, "Success", "Software asset updated.")
        else:
            sw_id = self.db.add_software_asset(os_name, version, manufacturer)
            self.db.link_software_to_hardware(sw_id, hardware_id)
            QMessageBox.information(self, "Success", "Software asset added and linked.")

        if self.refresh_callback:
            self.refresh_callback()
        self.close()

class EditEmployeeForm(QWidget):

    def __init__(self, db, employee, refresh_callback=None):
        super().__init__()
        self.db = db
        self.employee = employee
        self.refresh_callback = refresh_callback
        self.setWindowTitle("Edit Employee")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.first_input = QLineEdit(self.employee[1])
        self.last_input = QLineEdit(self.employee[2])
        self.email_input = QLineEdit(self.employee[3])
        self.dept_label = QLabel(self.employee[4])
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save_employee)
        layout.addWidget(QLabel("First Name:")); layout.addWidget(self.first_input)
        layout.addWidget(QLabel("Last Name:")); layout.addWidget(self.last_input)
        layout.addWidget(QLabel("Email:")); layout.addWidget(self.email_input)
        layout.addWidget(QLabel("Department:")); layout.addWidget(self.dept_label)
        layout.addWidget(save_btn)
        self.setLayout(layout)

    def save_employee(self):
        fn = self.first_input.text().strip()
        ln = self.last_input.text().strip()
        email = self.email_input.text().strip()
        if not all([fn, ln, email]):
            QMessageBox.warning(self, "Incomplete", "Please complete all fields.")
            return
        self.db.update_employee(self.employee[0], fn, ln, email)
        QMessageBox.information(self, "Success", "Employee updated.")
        if self.refresh_callback:
            self.refresh_callback()
        self.close()

class EditHardwareAssetForm(QWidget):
    def __init__(self, db, hw_asset, refresh_callback=None):
        super().__init__()
        self.db = db
        self.hw_asset = hw_asset
        self.refresh_callback = refresh_callback
        self.setWindowTitle("Edit Hardware Asset")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.sysname_input = QLineEdit(self.hw_asset[1])
        self.model_input = QLineEdit(self.hw_asset[2])
        self.manufacturer_input = QLineEdit(self.hw_asset[3])
        self.asset_type_input = QLineEdit(self.hw_asset[4])
        self.ip_input = QLineEdit(self.hw_asset[5])
        self.date_input = QDateEdit(calendarPopup=True)
        self.date_input.setDate(self.hw_asset[6])
        self.note_input = QTextEdit(self.hw_asset[7])
        self.employee_dropdown = QComboBox()
        self.employee_map = {}
        for emp_id, fname, lname, _, _ in self.db.get_employees():
            label = f"{fname} {lname}"
            self.employee_dropdown.addItem(label)
            self.employee_map[label] = emp_id
        for label, eid in self.employee_map.items():
            if eid == self.hw_asset[8]:
                self.employee_dropdown.setCurrentText(label)
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save_hw)
        layout.addWidget(QLabel("System Name:")); layout.addWidget(self.sysname_input)
        layout.addWidget(QLabel("Model:")); layout.addWidget(self.model_input)
        layout.addWidget(QLabel("Manufacturer:")); layout.addWidget(self.manufacturer_input)
        layout.addWidget(QLabel("Asset Type:")); layout.addWidget(self.asset_type_input)
        layout.addWidget(QLabel("IP Address:")); layout.addWidget(self.ip_input)
        layout.addWidget(QLabel("Purchase Date:")); layout.addWidget(self.date_input)
        layout.addWidget(QLabel("Note:")); layout.addWidget(self.note_input)
        layout.addWidget(QLabel("Assign to Employee:")); layout.addWidget(self.employee_dropdown)
        layout.addWidget(save_btn)
        self.setLayout(layout)

    def save_hw(self):
        eid = self.employee_map[self.employee_dropdown.currentText()]
        self.db.update_hardware_asset(
            self.hw_asset[0], self.sysname_input.text(), self.model_input.text(), self.manufacturer_input.text(),
            self.asset_type_input.text(), self.ip_input.text(), self.date_input.date().toPyDate(),
            self.note_input.toPlainText(), eid
        )
        QMessageBox.information(self, "Success", "Hardware asset updated.")
        if self.refresh_callback:
            self.refresh_callback()
        self.close()

class SoftwareAssetTable(QWidget):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.setWindowTitle("Software Asset Management")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.table = QTableWidget()
        self.refresh_table()
        add_btn = QPushButton("Add Software")
        add_btn.clicked.connect(self.open_add)
        layout.addWidget(self.table)
        layout.addWidget(add_btn)
        self.setLayout(layout)

    def refresh_table(self):
        data = self.db.get_software_assets()
        self.table.setColumnCount(6)
        self.table.setRowCount(len(data))
        self.table.setHorizontalHeaderLabels(["ID", "Name", "Version", "Manufacturer", "Edit", "Delete"])
        for row, asset in enumerate(data):
            for col in range(4):
                self.table.setItem(row, col, QTableWidgetItem(str(asset[col])))
            edit_btn = QPushButton("Edit")
            edit_btn.clicked.connect(lambda _, a=asset: self.open_edit(a))
            del_btn = QPushButton("Delete")
            del_btn.clicked.connect(lambda _, aid=asset[0]: self.delete_software(aid))
            self.table.setCellWidget(row, 4, edit_btn)
            self.table.setCellWidget(row, 5, del_btn)

    def open_add(self):
        self.form = AddSoftwareAssetForm(self.db, refresh_callback=self.refresh_table)
        self.form.show()

    def open_edit(self, asset):
        self.edit_form = AddSoftwareAssetForm(self.db, edit_asset=asset, refresh_callback=self.refresh_table)
        self.edit_form.show()

    def delete_software(self, asset_id):
        reply = QMessageBox.question(self, "Confirm Delete", "Delete this software asset?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.db.delete_software_asset(asset_id)
            self.refresh_table()

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
        self.dept_select.addItems([
            "information technology", "sales", "finance", "operations", "human resources"
        ])
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
        self.sysname_input = QLineEdit(platform.node())
        self.model_input = QLineEdit(platform.machine())
        self.manufacturer_input = QLineEdit(platform.system())
        self.asset_type_input = QLineEdit("PC")
        self.ip_input = QLineEdit(socket.gethostbyname(socket.gethostname()))
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
        layout.addWidget(QLabel("System Name:"))
        layout.addWidget(self.sysname_input)
        layout.addWidget(QLabel("Model:"))
        layout.addWidget(self.model_input)
        layout.addWidget(QLabel("Manufacturer:"))
        layout.addWidget(self.manufacturer_input)
        layout.addWidget(QLabel("Asset Type:"))
        layout.addWidget(self.asset_type_input)
        layout.addWidget(QLabel("IP Address:"))
        layout.addWidget(self.ip_input)
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
            self.sysname_input.text(),
            self.model_input.text(),
            self.manufacturer_input.text(),
            self.asset_type_input.text(),
            self.ip_input.text(),
            self.date_input.date().toPyDate(),
            self.note_input.toPlainText(),
            employee_id
        )
        QMessageBox.information(self, "Success", "Hardware asset recorded.")
        self.close()

class PersonalAssetViewer(QWidget):
    def __init__(self, db, user_id):
        super().__init__()
        self.db = db
        self.user_id = user_id
        self.setWindowTitle("My Assets")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        hw_assets = self.db.get_assets_for_employee(self.user_id)
        sw_assets = self.db.get_software_for_employee(self.user_id)
        layout.addWidget(QLabel("Hardware Assigned:"))
        for a in hw_assets:
            layout.addWidget(QLabel(f"{a[0]} - {a[1]} by {a[2]}"))
        layout.addWidget(QLabel("\nSoftware Assigned:"))
        for s in sw_assets:
            layout.addWidget(QLabel(f"{s[0]} version {s[1]}"))
        self.setLayout(layout)

class EditEmployeeForm(QWidget):
    def __init__(self, db, employee, refresh_callback=None):
        super().__init__()
        self.db = db
        self.employee = employee  # tuple: (id, fname, lname, email, dept)
        self.refresh_callback = refresh_callback
        self.setWindowTitle("Edit Employee")
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.first_input = QLineEdit(self.employee[1])
        self.last_input = QLineEdit(self.employee[2])
        self.email_input = QLineEdit(self.employee[3])
        self.dept_label = QLabel(self.employee[4])
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save_employee)
        layout.addWidget(QLabel("First Name:")); layout.addWidget(self.first_input)
        layout.addWidget(QLabel("Last Name:")); layout.addWidget(self.last_input)
        layout.addWidget(QLabel("Email:")); layout.addWidget(self.email_input)
        layout.addWidget(QLabel("Department:")); layout.addWidget(self.dept_label)
        layout.addWidget(save_btn)
        self.setLayout(layout)
    
    def save_employee(self):
        fn = self.first_input.text().strip()
        ln = self.last_input.text().strip()
        email = self.email_input.text().strip()
        if not all([fn, ln, email]):
            QMessageBox.warning(self, "Incomplete", "Please complete all fields.")
            return
        cursor = self.db.conn.cursor()
        cursor.execute(
            "UPDATE employees SET first_name=%s, last_name=%s, email=%s WHERE id=%s",
            (fn, ln, email, self.employee[0])
        )
        self.db.conn.commit()
        QMessageBox.information(self, "Success", "Employee updated.")
        if self.refresh_callback:
            self.refresh_callback()
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
        # EMPLOYEES
        self.emp_table = QTableWidget()
        employees = self.db.get_employees()
        self.emp_table.setColumnCount(8)
        self.emp_table.setRowCount(len(employees))
        self.emp_table.setHorizontalHeaderLabels([
            "ID", "Name", "Email", "Department", "Hardware Assets", "Software Assets", "Edit", "Delete"
        ])
        for i, (emp_id, fname, lname, email, dept) in enumerate(employees):
            full_name = f"{fname} {lname}"
            hw_assets = self.db.get_assets_for_employee(emp_id)
            sw_assets = self.db.get_software_for_employee(emp_id)
            hw_info = "; ".join([f"{a[0]} - {a[1]}" for a in hw_assets]) if hw_assets else "None"
            sw_info = "; ".join([f"{a[0]} {a[1]}" for a in sw_assets]) if sw_assets else "None"
            self.emp_table.setItem(i, 0, QTableWidgetItem(str(emp_id)))
            self.emp_table.setItem(i, 1, QTableWidgetItem(full_name))
            self.emp_table.setItem(i, 2, QTableWidgetItem(email))
            self.emp_table.setItem(i, 3, QTableWidgetItem(dept))
            self.emp_table.setItem(i, 4, QTableWidgetItem(hw_info))
            self.emp_table.setItem(i, 5, QTableWidgetItem(sw_info))
            # Edit
            edit_btn = QPushButton("Edit")
            edit_btn.clicked.connect(lambda _, e=(emp_id, fname, lname, email, dept): self.open_edit_employee(e))
            self.emp_table.setCellWidget(i, 6, edit_btn)
            # Delete
            del_btn = QPushButton("Delete")
            del_btn.clicked.connect(lambda _, eid=emp_id: self.delete_employee(eid))
            self.emp_table.setCellWidget(i, 7, del_btn)
        layout.addWidget(QLabel("Employees:"))
        layout.addWidget(self.emp_table)

        # HARDWARE
        self.hw_table = QTableWidget()
        hw_assets = self.db.get_hardware_assets()
        self.hw_table.setColumnCount(11)
        self.hw_table.setRowCount(len(hw_assets))
        self.hw_table.setHorizontalHeaderLabels([
            "ID", "System Name", "Model", "Manufacturer", "Type", "IP", "Date", "Note", "Employee", "Edit", "Delete"
        ])
        emp_map = {e[0]: f"{e[1]} {e[2]}" for e in employees}
        for i, asset in enumerate(hw_assets):
            for col in range(9):
                if col == 8:
                    emp_name = emp_map.get(asset[8], "None")
                    self.hw_table.setItem(i, 8, QTableWidgetItem(emp_name))
                else:
                    self.hw_table.setItem(i, col, QTableWidgetItem(str(asset[col])))
            # Edit
            edit_btn = QPushButton("Edit")
            edit_btn.clicked.connect(lambda _, a=asset: self.open_edit_hardware(a))
            self.hw_table.setCellWidget(i, 9, edit_btn)
            # Delete
            del_btn = QPushButton("Delete")
            del_btn.clicked.connect(lambda _, aid=asset[0]: self.delete_hardware(aid))
            self.hw_table.setCellWidget(i, 10, del_btn)
        layout.addWidget(QLabel("Hardware:"))
        layout.addWidget(self.hw_table)

        self.setLayout(layout)

    def open_edit_employee(self, employee):
        self.edit_emp_form = EditEmployeeForm(self.db, employee, refresh_callback=self.refresh_all)
        self.edit_emp_form.show()

    def delete_employee(self, emp_id):
        if not self.db.can_delete_employee(emp_id):
            QMessageBox.warning(self, "Error", "Cannot delete employee; hardware assigned.")
            return
        confirm = QMessageBox.question(self, "Delete", "Are you sure you want to delete this employee?", QMessageBox.Yes | QMessageBox.No)
        if confirm == QMessageBox.Yes:
            self.db.delete_employee(emp_id)
            self.refresh_all()

    def open_edit_hardware(self, hw_asset):
        self.edit_hw_form = EditHardwareAssetForm(self.db, hw_asset, refresh_callback=self.refresh_all)
        self.edit_hw_form.show()

    def delete_hardware(self, hw_id):
        if not self.db.can_delete_hardware(hw_id):
            QMessageBox.warning(self, "Error", "Cannot delete hardware; software linked.")
            return
        confirm = QMessageBox.question(self, "Delete", "Are you sure you want to delete this hardware asset?", QMessageBox.Yes | QMessageBox.No)
        if confirm == QMessageBox.Yes:
            self.db.delete_hardware_asset(hw_id)
            self.refresh_all()

    def refresh_all(self):
        self.init_ui()



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
        add_hw_btn.clicked.connect(lambda: self.open_hw_form())
        if self.department.lower() == "information technology":
            emp_btn = QPushButton("Open Employee Monitor")
            emp_btn.clicked.connect(self.open_monitor)
            layout.addWidget(emp_btn)
        central.setLayout(layout)
        self.setCentralWidget(central)

    def open_monitor(self):
        self.monitor = EmployeeMonitor(self.db, self.department)
        self.monitor.show()
    def open_hw_form(self):
        self.hw_form = AddHardwareAssetForm(self.db)
        self.hw_form.show()

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
            self.menu = MainWindow(self.db, user_id, department)
            self.menu.show()
            self.close()
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid credentials.")

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
