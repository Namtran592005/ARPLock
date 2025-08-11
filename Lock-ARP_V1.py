import sys
import os
import subprocess
import re
import ctypes
from PyQt5 import QtWidgets, QtCore, QtGui

# ----------------------
# Helpers
# ----------------------

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def relaunch_as_admin():
    if getattr(sys, 'frozen', False):
        executable = sys.executable
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    else:
        executable = sys.executable
        params = " ".join([f'"{arg}"' for arg in sys.argv])

    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 1)
    except Exception as e:
        QtWidgets.QMessageBox.critical(None, "Error",
                                       f"Failed to relaunch as Administrator: {e}")
    sys.exit(0)

def run_cmd(cmd_list, capture_output=True, timeout=10):
    startupinfo = None
    creationflags = 0
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        creationflags = subprocess.CREATE_NO_WINDOW

    try:
        proc = subprocess.run(
            cmd_list,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            shell=False,
            startupinfo=startupinfo,
            creationflags=creationflags
        )
        stdout_str = (proc.stdout or "").strip()
        stderr_str = (proc.stderr or "").strip()
        return proc.returncode, stdout_str, stderr_str
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out."
    except FileNotFoundError:
        return -1, "", f"Command '{cmd_list[0]}' not found."
    except Exception as e:
        return -1, "", str(e)

def get_default_gateway():
    rc, out, err = run_cmd(["ipconfig"], capture_output=True)
    if rc != 0:
        return None
    m = re.search(r"Default Gateway[ \.\:]*\s*([\d]+\.[\d]+\.[\d]+\.[\d]+)", out)
    if m:
        return m.group(1)
    return None

def get_mac_for_ip(ip):
    run_cmd(["ping", "-n", "1", "-w", "1000", ip], capture_output=True, timeout=2)
    rc, out, err = run_cmd(["arp", "-a"], capture_output=True)
    if rc != 0:
        return None
    
    for line in out.splitlines():
        if ip in line:
            m = re.search(r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})", line)
            if m:
                mac = m.group(1).replace(":", "-").lower()
                return mac
    return None

# ----------------------
# GUI App
# ----------------------
class LockArpApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Lock ARP — Lock/Restore Gateway ARP")
        self.setMinimumSize(700, 400)

        self.gateway_ip = None
        self.gateway_mac = None
        self.locked = False

        self.apply_dark_theme()

        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(18)
        self.setLayout(layout)

        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        log_font = QtGui.QFont("Consolas")
        log_font.setPointSize(10)
        self.log.setFont(log_font)
        layout.addWidget(self.log)

        self._set_window_icon()

        info_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(info_layout)

        self.lbl_gateway = QtWidgets.QLabel("Gateway: —")
        self.lbl_mac = QtWidgets.QLabel("MAC: —")
        self.lbl_status = QtWidgets.QLabel("Status: Unknown")

        font = QtGui.QFont()
        font.setPointSize(12)
        self.lbl_gateway.setFont(font)
        self.lbl_mac.setFont(font)
        self.lbl_status.setFont(font)
        self.lbl_status.setStyleSheet("font-weight: bold;")

        info_layout.addWidget(self.lbl_gateway)
        info_layout.addSpacing(25)
        info_layout.addWidget(self.lbl_mac)
        info_layout.addStretch()
        info_layout.addWidget(self.lbl_status)

        btn_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(btn_layout)

        self.btn_refresh = QtWidgets.QPushButton("Refresh") # Đổi tên nút ngắn gọn hơn
        self.btn_lock = QtWidgets.QPushButton("Lock ARP")
        self.btn_restore = QtWidgets.QPushButton("Restore ARP")

        self._apply_button_styles()

        self.btn_lock.setEnabled(False)
        self.btn_restore.setEnabled(False)

        btn_layout.addWidget(self.btn_refresh)
        btn_layout.addWidget(self.btn_lock)
        btn_layout.addWidget(self.btn_restore)
        btn_layout.addStretch()
        
        self.btn_refresh.clicked.connect(self.do_refresh)
        self.btn_lock.clicked.connect(self.do_lock)
        self.btn_restore.clicked.connect(self.do_restore)

        QtCore.QTimer.singleShot(100, self.do_refresh)

    def _set_window_icon(self):
        if getattr(sys, 'frozen', False):
            icon_path = os.path.join(sys._MEIPASS, 'icon.png')
        else:
            icon_path = 'icon.png'

        if os.path.exists(icon_path):
            self.setWindowIcon(QtGui.QIcon(icon_path))
        else:
            self.log_line(f"[WARN] Icon not found at: {icon_path}.") # Giảm log, chỉ ghi WARN

    def apply_dark_theme(self):
        dark_stylesheet = """
            QWidget {
                background-color: #222222;
                color: #e0e0e0;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 10pt;
            }
            QLabel {
                color: #e0e0e0;
            }
            QPlainTextEdit {
                background-color: #2b2b2b;
                color: #f0f0f0;
                border: 1px solid #444444;
                border-radius: 6px;
                padding: 8px;
                selection-background-color: #0056b3;
            }
            QScrollBar:vertical {
                border: none;
                background: #3a3a3a;
                width: 12px;
                margin: 0px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background: #555555;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
            QMessageBox {
                background-color: #2e2e2e;
                color: #e0e0e0;
                font-size: 10pt;
            }
            QMessageBox QLabel {
                color: #e0e0e0;
            }
            QMessageBox QPushButton {
                background-color: #007bff;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 5px;
                font-size: 10pt;
            }
            QMessageBox QPushButton:hover {
                background-color: #0056b3;
            }
        """
        self.setStyleSheet(dark_stylesheet)
        palette = QtGui.QPalette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor("#2e2e2e"))
        palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor("#e0e0e0"))
        palette.setColor(QtGui.QPalette.Button, QtGui.QColor("#007bff"))
        palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor("white"))
        QtWidgets.QApplication.setPalette(palette)

    def _apply_button_styles(self):
        btn_base_style = """
            QPushButton {
                color: white;
                font-size: 15px;
                font-weight: bold;
                padding: 12px 25px;
                border-radius: 8px;
                border: 1px solid;
                transition: all 0.2s ease-in-out;
            }
            QPushButton:hover {
                transform: translateY(-2px);
            }
            QPushButton:pressed {
                transform: translateY(0);
            }
            QPushButton:disabled {
                background-color: #505050;
                border: 1px solid #3a3a3a;
                color: #b0b0b0;
            }
        """

        self.btn_refresh.setStyleSheet(btn_base_style + """
            QPushButton {
                background-color: #28a745;
                border-color: #218838;
            }
            QPushButton:hover {
                background-color: #218838;
            }
            QPushButton:pressed {
                background-color: #1e7e34;
            }
        """)

        self.btn_lock.setStyleSheet(btn_base_style + """
            QPushButton {
                background-color: #dc3545;
                border-color: #c82333;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
            QPushButton:pressed {
                background-color: #bd2130;
            }
        """)

        self.btn_restore.setStyleSheet(btn_base_style + """
            QPushButton {
                background-color: #007bff;
                border-color: #0069d9;
            }
            QPushButton:hover {
                background-color: #0069d9;
            }
            QPushButton:pressed {
                background-color: #0062cc;
            }
        """)

    def log_line(self, *parts):
        txt = " ".join(str(p) for p in parts)
        timestamp = QtCore.QDateTime.currentDateTime().toString("HH:mm:ss")
        self.log.appendPlainText(f"[{timestamp}] {txt}")
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())

    def set_status(self, text, color=None):
        self.lbl_status.setText(f"Status: {text}")
        if color:
            self.lbl_status.setStyleSheet(f"font-weight:bold; color: {color};")
        else:
            self.lbl_status.setStyleSheet("font-weight:bold; color: #e0e0e0;")

    def do_refresh(self):
        self.log_line("[Info] Refreshing...") # Giảm log
        self.set_status("Detecting...", "#FFA500")

        gw = get_default_gateway()
        if not gw:
            self.lbl_gateway.setText("Gateway: —")
            self.lbl_mac.setText("MAC: —")
            self.btn_lock.setEnabled(False)
            self.btn_restore.setEnabled(False)
            self.set_status("No Gateway", "red")
            QtWidgets.QMessageBox.warning(self, "Error", "No Default Gateway found. Ensure network connection.")
            self.log_line("[Error] No Gateway found.") # Giảm log
            return
        
        self.gateway_ip = gw
        self.lbl_gateway.setText(f"Gateway: {gw}")
        
        mac = get_mac_for_ip(gw)
        if not mac:
            self.lbl_mac.setText("MAC: —")
            self.btn_lock.setEnabled(False)
            self.btn_restore.setEnabled(False)
            self.set_status("No MAC", "red")
            QtWidgets.QMessageBox.warning(self, "Error", f"Could not get MAC for Gateway ({gw}). Check network.")
            self.log_line(f"[Error] No MAC for {gw}.") # Giảm log
            return
        
        self.gateway_mac = mac
        self.lbl_mac.setText(f"MAC: {mac}")
        self.log_line(f"[Success] Gateway: {gw} -> {mac}") # Giảm log
        
        rc, out, err = run_cmd(["arp", "-a", self.gateway_ip])
        is_static = False
        if rc == 0:
            for line in out.splitlines():
                if self.gateway_ip in line and self.gateway_mac in line:
                    if "static" in line.lower():
                        is_static = True
                        break
        
        self.locked = is_static
        if self.locked:
            self.set_status("Locked", "red")
            self.btn_lock.setEnabled(False)
            self.btn_restore.setEnabled(True)
            self.log_line("[Info] ARP is currently Locked (static).") # Giảm log
        else:
            self.set_status("Unlocked", "green")
            self.btn_lock.setEnabled(True)
            self.btn_restore.setEnabled(True)
            self.log_line("[Info] ARP is currently Unlocked (dynamic).") # Giảm log


    def do_lock(self):
        if not self.gateway_ip or not self.gateway_mac:
            QtWidgets.QMessageBox.warning(self, "Error", "No Gateway/MAC info. Click Refresh first.")
            self.log_line("[Error] Cannot lock without Gateway/MAC info.") # Giảm log
            return
        
        if not is_admin():
            answer = QtWidgets.QMessageBox.question(self, "Admin Privilege Required",
                                                    "Locking ARP requires Administrator privileges. Relaunch as admin?",
                                                    QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                                    QtWidgets.QMessageBox.Yes)
            if answer == QtWidgets.QMessageBox.Yes:
                self.log_line("[Info] Relaunching as admin for Lock operation.") # Giảm log
                relaunch_as_admin()
            return

        ip = self.gateway_ip
        mac = self.gateway_mac

        self.log_line(f"[Info] Deleting old ARP entry for {ip}...") # Giảm log
        rc, out, err = run_cmd(["arp", "-d", ip])
        if rc != 0:
            self.log_line(f"[Warning] 'arp -d {ip}' failed (code: {rc}): {err}") # Giảm log

        self.log_line(f"[Info] Adding static ARP: {ip} -> {mac}") # Giảm log
        rc2, out2, err2 = run_cmd(["arp", "-s", ip, mac])
        if rc2 == 0:
            self.log_line("[Success] ARP Locked successfully.") # Giảm log
            self.locked = True
            self.set_status("Locked", "red")
            self.btn_lock.setEnabled(False)
            self.btn_restore.setEnabled(True)
            QtWidgets.QMessageBox.information(self, "Success", f"ARP Locked for:\nIP: {ip}\nMAC: {mac}")
        else:
            self.log_line(f"[Error] Failed to set static ARP (code: {rc2}): {err2}") # Giảm log
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to set static ARP.\nError: {err2}\nEnsure admin privileges.")
            self.set_status("Failed to Lock", "red")

    def do_restore(self):
        if not self.gateway_ip:
            QtWidgets.QMessageBox.warning(self, "Error", "No Gateway info. Click Refresh first.")
            self.log_line("[Error] Cannot restore without Gateway info.") # Giảm log
            return
        
        if not is_admin():
            answer = QtWidgets.QMessageBox.question(self, "Admin Privilege Required",
                                                    "Restoring ARP requires Administrator privileges. Relaunch as admin?",
                                                    QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                                    QtWidgets.QMessageBox.Yes)
            if answer == QtWidgets.QMessageBox.Yes:
                self.log_line("[Info] Relaunching as admin for Restore operation.") # Giảm log
                relaunch_as_admin()
            return

        ip = self.gateway_ip
        self.log_line(f"[Info] Deleting ARP entry for {ip}...") # Giảm log
        rc, out, err = run_cmd(["arp", "-d", ip])

        if rc == 0:
            self.log_line(f"[Success] ARP entry deleted for {ip}.") # Giảm log
            QtWidgets.QMessageBox.information(self, "Success", f"ARP restored (static entry deleted) for {ip}.")
        else:
            self.log_line(f"[Warning] 'arp -d {ip}' failed (code: {rc}): {err}. Trying to delete all.") # Giảm log
            
            reply = QtWidgets.QMessageBox.warning(self, "Warning",
                                                 f"Could not delete specific ARP entry for {ip} (code: {rc}).\n"
                                                 "This may happen if the entry doesn't exist or changed.\n"
                                                 "Attempt to delete ALL ARP entries to ensure no static ARP remains?\n"
                                                 "This may temporarily disrupt network connectivity.",
                                                 QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                                 QtWidgets.QMessageBox.No)
            if reply == QtWidgets.QMessageBox.Yes:
                self.log_line("[Info] User chose to delete all ARP entries.") # Giảm log
                rc2, out2, err2 = run_cmd(["arp", "-d", "*"])
                if rc2 == 0:
                    self.log_line("[Success] All ARP entries deleted.") # Giảm log
                    QtWidgets.QMessageBox.information(self, "Success", "All ARP entries have been deleted.")
                else:
                    self.log_line(f"[Error] Failed to delete all ARP entries (code: {rc2}): {err2}") # Giảm log
                    QtWidgets.QMessageBox.critical(self, "Error", f"Failed to delete all ARP.\nError: {err2}\nTry restarting your computer.")
                    self.set_status("Failed to Restore", "red")
                    return
            else:
                self.log_line("[Info] User cancelled deleting all ARP entries. Restore incomplete.") # Giảm log
                QtWidgets.QMessageBox.information(self, "Operation Cancelled", "Restore operation cancelled or incomplete.")
                self.set_status("Restore Cancelled", "orange")
                return

        self.locked = False
        self.set_status("Unlocked", "green")
        self.btn_lock.setEnabled(True)
        self.btn_restore.setEnabled(False)
        QtCore.QTimer.singleShot(500, self.do_refresh)

# ----------------------
# Main Application Entry
# ----------------------
def main():
    if os.name != "nt":
        print("This application runs only on Windows.", file=sys.stderr)
        sys.exit(1)

    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("Lock ARP Tool")

    w = LockArpApp()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()