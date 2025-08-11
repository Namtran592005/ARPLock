# -*- coding: utf-8 -*-
"""
ARP Guardian
A Python-based application to protect against ARP spoofing attacks on Windows.
Features:
- Automatic ARP lock for the default gateway.
- Proactive ARP Stealth (only reply to router's ARP requests).
- System tray integration and run-on-startup.
- Advanced stealth features via Windows Firewall and Registry.
- Admin privileges required.
"""

import sys
import os
import subprocess
import time
import re
import logging
import winreg
import win32api
import win32security
import win32con
from ctypes import windll, wintypes
import json # Explicitly import json

# --- Scapy Imports (Conditional import as Scapy requires Npcap) ---
_has_scapy = False
try:
    from scapy.all import ARP, Ether, sniff, send, get_if_hwaddr, conf, srp, get_if_list, get_working_if
    SCAPY_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scapy_cache")
    if not os.path.exists(SCAPY_CACHE_DIR):
        os.makedirs(SCAPY_CACHE_DIR)
    conf.cache_dir = SCAPY_CACHE_DIR
    logging.info(f"Scapy cache directory set to: {conf.cache_dir}")
    _has_scapy = True
except ImportError:
    logging.warning("Scapy is not installed. ARP Stealth features will be disabled. Install with 'pip install scapy'.")
except Exception as e:
    _has_scapy = False
    logging.error(f"Error importing Scapy: {e}. ARP Stealth features will be disabled. Ensure Npcap is installed and you run as Admin.")

try:
    from PIL import Image
    _has_pillow = True
except ImportError:
    _has_pillow = False
    logging.warning("Pillow is not installed. Default icon creation will be disabled. Install with 'pip install Pillow'.")

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QCheckBox, QSystemTrayIcon, QMenu,
    QAction, QMessageBox, QLineEdit, QGroupBox, QDialog, QSizePolicy,
    QSpinBox, QFormLayout, QDialogButtonBox, QTabWidget, QScrollArea,
    QComboBox
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize
)
from PyQt5.QtGui import QIcon, QFont, QColor, QTextCharFormat, QTextCursor, QTextDocument, QPalette, QBrush

# --- Global Constants & Setup ---
APP_NAME = "ARP Guardian"
APP_VERSION = "BETA" # Version bumped for run_lock_arp.py philosophy
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "arp_guardian.log")
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.ini")
ICON_FILE = os.path.join(SCRIPT_DIR, "icon.png")
RUN_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

# For Windows, to suppress console window for subprocesses
if sys.platform == "win32":
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags = subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE # 0
    _creationflags = subprocess.CREATE_NO_WINDOW
else:
    startupinfo = None
    _creationflags = 0

# --- Logging Configuration ---
def setup_logging():
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        if isinstance(handler, logging.StreamHandler):
            root_logger.removeHandler(handler)

    logging.basicConfig(
        level=logging.INFO, # Keep INFO for general operation, use DEBUG for deep troubleshooting
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE, encoding='utf-8')
        ]
    )
    logging.info(f"{APP_NAME} v{APP_VERSION} Started.")

# --- Utility Functions ---
def is_admin():
    """Checks if the current process has administrative privileges."""
    try:
        return windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logging.error(f"Error checking admin rights using shell32: {e}")
        return False

def restart_as_admin():
    """Restarts the current application with administrative privileges."""
    script_path = os.path.abspath(sys.argv[0])
    try:
        python_exe = sys.executable
        if python_exe.endswith('python.exe') and os.path.exists(python_exe.replace('python.exe', 'pythonw.exe')):
            python_exe = python_exe.replace('python.exe', 'pythonw.exe')
        
        if script_path.endswith('.py'):
            command_args = f'"{script_path}"'
            executable_to_run = f'"{python_exe}"'
        else:
            command_args = ""
            executable_to_run = f'"{script_path}"'
            
        win32api.ShellExecute(
            0, "runas", executable_to_run, command_args, None, 1 # 1 for SW_SHOWNORMAL
        )
        sys.exit(0)
    except Exception as e:
        logging.critical(f"Failed to restart as admin: {e}")
        QMessageBox.critical(None, "Lỗi Quyền Admin",
                             "Không thể khởi động lại chương trình với quyền quản trị.\n"
                             "Vui lòng chạy lại chương trình với quyền Admin theo cách thủ công.")
        sys.exit(1)

def run_powershell_command(command: str, name: str = "PowerShell Command") -> tuple[bool, str]:
    """
    Executes a PowerShell command.
    Returns (True/False, stdout/stderr)
    """
    try:
        full_command = f"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"{command}\""
        logging.debug(f"Executing PS Command '{name}': {command}")
        result = subprocess.run(full_command, capture_output=True, text=True, check=False,
                                startupinfo=startupinfo, creationflags=_creationflags)
        if result.returncode != 0:
            logging.error(f"Lỗi khi chạy lệnh PowerShell '{name}' (Exit Code: {result.returncode}): {result.stderr.strip()}")
            return False, result.stderr.strip()
        else:
            logging.debug(f"Chạy lệnh PowerShell '{name}' thành công. Output: {result.stdout.strip()}")
            return True, result.stdout.strip()
    except Exception as e:
        logging.error(f"Lỗi hệ thống khi chạy lệnh PowerShell '{name}': {e}")
        return False, str(e)


def list_all_network_adapters() -> list[dict]:
    """
    Lists all network adapters (active or disconnected) with their friendly name, GUID, MAC, IfIndex, and status.
    Returns a list of dictionaries: [{'name': '...', 'guid': '...', 'mac': '...', 'ifindex': ..., 'status': '...'}, ...]
    """
    adapters = []
    try:
        cmd = "Get-NetAdapter | Select-Object -Property Name, InterfaceDescription, InterfaceGuid, MacAddress, IfIndex, Status | ConvertTo-Json"
        success, output = run_powershell_command(cmd, "List All Network Adapters")
        
        if success and output:
            try:
                data = json.loads(output.strip())
                adapter_list = data if isinstance(data, list) else [data]

                for adapter_info in adapter_list:
                    name = adapter_info.get("Name")
                    description = adapter_info.get("InterfaceDescription")
                    guid = adapter_info.get("InterfaceGuid")
                    status = adapter_info.get("Status")
                    mac = adapter_info.get("MacAddress")
                    ifindex = adapter_info.get("ifIndex") # Corrected case here

                    if name and guid and mac and ifindex is not None:
                        adapters.append({
                            'name': name,
                            'description': description if description else name,
                            'guid': guid.replace('{', '').replace('}', ''), # Remove curly braces
                            'status': status if status else 'Unknown',
                            'mac': mac.replace('-', ':'), # Standardize MAC format
                            'ifindex': ifindex
                        })
            except json.JSONDecodeError as e:
                logging.warning(f"Failed to parse JSON for network adapters: {e}. Raw output: {output[:500]}...")
            except Exception as e:
                logging.error(f"Error processing network adapter list: {e}")
        else:
            logging.warning(f"Không thể liệt kê card mạng. Lỗi PowerShell: {output}")

    except Exception as e:
        logging.error(f"Lỗi hệ thống khi liệt kê card mạng: {e}")
    return adapters

def get_network_info_for_adapter(adapter_name: str) -> dict | None:
    """
    Retrieves detailed network information (Host IP, Gateway IP, MAC, GUID, IfIndex, Network ID)
    for a specific adapter name using PowerShell.
    This consolidates calls similar to get_network_info_via_powershell but for a known adapter.
    Returns a dictionary of info or None if not found/active.
    """
    logging.debug(f"Attempting to get detailed info for adapter: '{adapter_name}'")
    
    info = {
        "gateway_ip": None, "host_ip": None, "host_mac": None, 
        "adapter_name": adapter_name, "adapter_guid": None, "ifindex": None, 
        "network_id": None # ProfileGuid
    }

    try:
        # Step 1: Get adapter's basic info (GUID, MAC, IfIndex, Status) using Get-NetAdapter
        cmd_adapter_info = f"Get-NetAdapter -Name '{adapter_name}' | Select-Object Name, InterfaceGuid, MacAddress, IfIndex, Status | ConvertTo-Json"
        success, output = run_powershell_command(cmd_adapter_info, f"Get Adapter Info for '{adapter_name}'")
        if not success or not output:
            logging.warning(f"Không thể lấy thông tin cơ bản cho adapter '{adapter_name}'. Lỗi: {output}")
            return None
        
        try:
            adapter_data = json.loads(output.strip())
            if isinstance(adapter_data, list) and len(adapter_data) > 0: adapter_data = adapter_data[0]
            
            if adapter_data.get("Status") != "Up":
                logging.warning(f"Adapter '{adapter_name}' không hoạt động (Status: {adapter_data.get('Status')}).")
                return None # Only proceed if adapter is Up
            
            info['adapter_guid'] = adapter_data.get("InterfaceGuid", "").replace('{', '').replace('}', '')
            info['host_mac'] = adapter_data.get("MacAddress", "").replace('-', ':')
            info['ifindex'] = adapter_data.get("ifIndex") # Corrected case

            if not (info['adapter_guid'] and info['host_mac'] and info['ifindex'] is not None):
                logging.error(f"Thông tin Adapter '{adapter_name}' bị thiếu (GUID/MAC/IfIndex).")
                return None
        except json.JSONDecodeError as e:
            logging.error(f"Lỗi parsing JSON adapter info cho '{adapter_name}': {e}. Output: {output}")
            return None

        # Step 2: Get Host IP and Gateway IP for this adapter using Get-NetIPConfiguration
        cmd_ip_config = f"""
        $ipConfig = (Get-NetAdapter -Name '{adapter_name}' | Get-NetIPConfiguration)
        $hostIp = $ipConfig.IPv4Address.IPAddress | Select-Object -First 1
        $gatewayIp = $ipConfig.IPv4DefaultGateway | Select-Object -First 1
        Write-Host "$($hostIp),$($gatewayIp)"
        """
        success, output = run_powershell_command(cmd_ip_config, f"Get IP Config for '{adapter_name}'")
        if success and output and "," in output:
            host_ip_str, gateway_ip_str = output.strip().split(',', 1)
            info['host_ip'] = host_ip_str if host_ip_str.strip() else None
            info['gateway_ip'] = gateway_ip_str if gateway_ip_str.strip() else None
        else:
            logging.warning(f"Không thể lấy Host IP/Gateway cho '{adapter_name}'. Lỗi/Output: {output}")

        if not (info['gateway_ip'] and info['host_ip']):
            logging.warning(f"Host IP hoặc Gateway IP bị thiếu cho adapter '{adapter_name}'.")
            return None

        # Step 3: Get Network ID (ProfileGuid) for this adapter
        cmd_net_profile = f"Get-NetConnectionProfile | Where-Object {{$_.InterfaceIndex -eq {info['ifindex']}}} | Select-Object -ExpandProperty ProfileGuid | ConvertTo-Json"
        success, output = run_powershell_command(cmd_net_profile, f"Get Net Profile GUID for '{adapter_name}'")
        if success and output:
            try:
                data = json.loads(output.strip())
                if isinstance(data, list) and len(data) > 0: info['network_id'] = data[0]
                elif isinstance(data, str): info['network_id'] = data
            except json.JSONDecodeError:
                logging.warning(f"Lỗi parsing JSON Net Profile GUID cho '{adapter_name}': {output}")
            except Exception as e:
                logging.error(f"Lỗi xử lý kết quả Get-NetConnectionProfile cho '{adapter_name}': {e}")
        else:
            logging.warning(f"Không thể lấy ID mạng (ProfileGuid) cho '{adapter_name}'. Lỗi: {output}")

        logging.info(f"Đã thu thập thông tin mạng chi tiết cho '{adapter_name}': {info}")
        return info

    except Exception as e:
        logging.error(f"Lỗi chung khi lấy thông tin mạng cho adapter '{adapter_name}': {e}")
    return None

def get_current_active_network_info(preferred_iface_name: str = None) -> dict | None:
    """
    Attempts to get network information (gateway, host IP, host MAC, adapter name, network ID)
    for the primary active network interface. Prioritizes preferred_iface_name.
    Returns a dict with relevant info or None if no active network is found.
    """
    logging.debug(f"Bắt đầu tìm thông tin mạng. Ưu tiên: '{preferred_iface_name}'")
    
    # Attempt 1: Try the preferred adapter if provided
    if preferred_iface_name:
        info = get_network_info_for_adapter(preferred_iface_name)
        if info and info['gateway_ip'] and info['host_ip'] and info['host_mac']:
            logging.info(f"Đã lấy thông tin mạng qua card ưu tiên '{preferred_iface_name}'.")
            return info
        logging.warning(f"Không thể lấy thông tin đầy đủ từ card ưu tiên '{preferred_iface_name}'. Thử tự động phát hiện.")

    # Attempt 2: Auto-detect primary active adapter via default route
    cmd_route = "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceIndex"
    success_route, output_route = run_powershell_command(cmd_route, "Get Default Route Interface Index")
    
    if success_route and output_route.strip().isdigit():
        default_route_ifindex = int(output_route.strip())
        
        # Now find the adapter matching this IfIndex and get its detailed info
        adapters = list_all_network_adapters()
        for adapter in adapters:
            if adapter.get('ifindex') == default_route_ifindex and adapter.get('status') == 'Up':
                info = get_network_info_for_adapter(adapter['name'])
                if info and info['gateway_ip'] and info['host_ip'] and info['host_mac']:
                    logging.info(f"Đã tự động lấy thông tin mạng qua card chính '{adapter['name']}'.")
                    return info
                logging.warning(f"Không thể lấy thông tin đầy đủ từ card chính tự động '{adapter['name']}'.")
    else:
        logging.warning(f"Không tìm thấy Default Route. Lỗi/Output: {output_route}")

    logging.warning("Không tìm thấy card mạng chính hoạt động nào có đầy đủ thông tin IP/Gateway/MAC. Vui lòng kiểm tra kết nối.")
    return None

def get_mac_from_arp_powershell(ip_address: str, retries: int = 3, ping_timeout_ms: int = 200) -> str | None:
    """
    Attempts to retrieve the MAC address for a given IP address using PowerShell's Get-NetNeighbor.
    Pings the IP first to ensure it's discoverable.
    Returns MAC string (XX:XX:XX:XX:XX:XX) or None.
    """
    if not ip_address:
        logging.error("Địa chỉ IP không được cung cấp để lấy MAC.")
        return None

    for attempt in range(retries):
        logging.debug(f"Pinging {ip_address} to populate ARP cache (Attempt {attempt + 1}).")
        # Ping to ensure entry in ARP table. Use cmd ping for simplicity.
        subprocess.run(['ping', '-n', '1', '-w', str(ping_timeout_ms), ip_address], 
                       capture_output=True, text=True, check=False, 
                       startupinfo=startupinfo, creationflags=_creationflags)
        time.sleep(0.5) # Small delay for ARP table to update

        # Use PowerShell to get NetNeighbor (ARP cache)
        cmd = f"""
        $neighbor = Get-NetNeighbor -IPAddress '{ip_address}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LinkLayerAddress
        if ($neighbor) {{ $neighbor | ConvertTo-Json }} else {{ "" }}
        """
        success, output = run_powershell_command(cmd, f"Get MAC for {ip_address} via Get-NetNeighbor")

        if success and output:
            try:
                mac_raw = json.loads(output.strip())
                if isinstance(mac_raw, list) and len(mac_raw) > 0: # Should not be a list for single IPAddress
                    mac_raw = mac_raw[0]
                elif not isinstance(mac_raw, str): # Handle `null` or other non-string if no result
                    mac_raw = ""
                
                if mac_raw and re.match(r"([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})", mac_raw):
                    mac = mac_raw.replace('-', ':').upper() # Ensure uppercase for consistency
                    logging.info(f"Tìm thấy MAC của {ip_address}: {mac} (ở lần thử {attempt + 1}) qua PowerShell.")
                    return mac
                else:
                    logging.debug(f"Get-NetNeighbor returned non-MAC or empty value for {ip_address}: '{mac_raw}'")
            except json.JSONDecodeError as e:
                logging.warning(f"Failed to parse JSON MAC from Get-NetNeighbor for {ip_address}: {e}. Output: {output}")
            except Exception as e:
                logging.warning(f"Error processing Get-NetNeighbor output for {ip_address}: {e}")

    logging.error(f"Thất bại khi lấy MAC cho IP {ip_address} sau {retries} lần thử (PowerShell).")
    return None


def set_static_arp(ip_address, mac_address):
    """Sets a static ARP entry."""
    max_set_retries = 2
    set_retry_delay_sec = 1
    
    formatted_mac = mac_address.replace(':', '-') # ARP command prefers hyphens

    logging.info(f"Đang cố gắng thêm ARP tĩnh: {ip_address} với MAC: {formatted_mac}")

    for attempt in range(max_set_retries):
        try:
            result = subprocess.run(['arp', '-s', ip_address, formatted_mac], capture_output=True, text=True, check=True,
                                    startupinfo=startupinfo, creationflags=_creationflags)
            logging.info(f"[*] Đã khóa ARP thành công: {ip_address} → {formatted_mac} (ở lần thử {attempt + 1}).")
            return True
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip()
            logging.error(f"Lỗi khi khóa ARP cho {ip_address} (Thử lần {attempt + 1}): {error_msg}")
            if "The ARP entry addition failed: Access Denied" in error_msg or "Quyền truy cập bị từ chối" in error_msg:
                logging.critical("Lỗi: Access Denied khi khóa ARP. Chắc chắn ứng dụng chạy với quyền Admin.")
                return False
            time.sleep(set_retry_delay_sec)
        except Exception as e:
            logging.error(f"Lỗi không xác định khi khóa ARP (Thử lần {attempt + 1}): {e}")
            time.sleep(set_retry_delay_sec)
    
    logging.error(f"Thất bại khi khóa ARP cho {ip_address} sau {max_set_retries} lần thử.")
    return False

def reset_arp_to_default(ip_address):
    """Resets the ARP entry for a given IP to default (dynamic) by deleting it."""
    try:
        logging.info(f"Đang cố gắng xóa ARP cho {ip_address}.")
        result = subprocess.run(['arp', '-d', ip_address], capture_output=True, text=True, check=False,
                       startupinfo=startupinfo, creationflags=_creationflags)
        if result.returncode == 0:
            logging.info(f"Đã reset ARP cho {ip_address} về mặc định.")
            return True
        else:
            if "not found" in result.stderr.strip().lower() or "không tìm thấy" in result.stderr.strip().lower():
                logging.info(f"Entry ARP cho {ip_address} không tồn tại, không cần xóa.")
                return True
            else:
                logging.warning(f"Không thể xóa ARP cho {ip_address}. Lỗi: {result.stderr.strip()}")
                return False
    except Exception as e:
        logging.error(f"Lỗi khi reset ARP cho {ip_address}: {e}")
        return False

# --- Configuration Management ---
class SettingsManager:
    def __init__(self):
        self.config = {}
        self.load_config()

    def load_config(self):
        """Loads configuration from config.ini or creates default if not found."""
        default_config = {
            "auto_lock_enabled": "True",
            "run_on_startup": "False",
            "last_locked_gateway": "",
            "last_locked_mac": "",
            "last_network_id": "", # Used for change detection (ProfileGuid)
            "last_host_ip": "", # Used for change detection
            "last_adapter_name": "", # Used for change detection
            "arp_stealth_enabled": "True",
            "periodic_check_interval": "5",
            "preferred_interface_name": "", # For user selection
            # Stealth settings
            "stealth_block_icmp": "False",
            "stealth_disable_ssdp": "False",
            "stealth_disable_upnphost": "False",
            "stealth_disable_fdrespub": "False",
            "stealth_block_netbios": "False",
            "stealth_block_llmnr": "False",
            "stealth_block_mdns": "False",
            "stealth_block_rpc_epmap": "False",
            "stealth_block_netbios_ssn": "False",
            "stealth_block_unknown_5040": "False",
            "stealth_disable_dhcp_hostname_reg": "False",
            "stealth_disable_remote_registry": "False",
            "stealth_disable_winrm": "False",
            "stealth_disable_rdp": "False",
            "stealth_block_smb": "False",
            "stealth_disable_lanmanserver": "False",
            "stealth_set_ttl_1": "False",
            "stealth_has_applied_any": "False"
        }

        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        self.config[key] = value
            logging.info(f"Đã tải cấu hình từ {CONFIG_FILE}")
            
            for key, value in default_config.items():
                if key not in self.config:
                    self.config[key] = value
                    logging.info(f"Thêm cài đặt mặc định mới: {key}={value}")

        except FileNotFoundError:
            logging.warning(f"File cấu hình {CONFIG_FILE} không tồn tại. Tạo mới.")
            self.config = default_config
            self.save_config()
        except Exception as e:
            logging.error(f"Lỗi khi tải cấu hình: {e}. Sử dụng cấu hình mặc định.")
            self.config = default_config

    def save_config(self):
        """Saves the current configuration to config.ini."""
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                for key, value in self.config.items():
                    f.write(f"{key}={value}\n")
            logging.info(f"Đã lưu cấu hình vào {CONFIG_FILE}")
        except Exception as e:
            logging.error(f"Lỗi khi lưu cấu hình: {e}")

    def get_setting(self, key, default=None):
        """Retrieves a setting by key, with an optional default value."""
        return self.config.get(key, default)

    def set_setting(self, key, value):
        """Sets a setting and immediately saves the configuration."""
        self.config[key] = str(value)
        self.save_config()

    def set_run_on_startup(self, enable):
        """Manages the application's startup entry in the Windows Registry."""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_REG_KEY, 0, winreg.KEY_ALL_ACCESS)
            app_path = os.path.abspath(sys.argv[0])
            
            python_exe = sys.executable
            if python_exe.endswith('python.exe') and os.path.exists(python_exe.replace('python.exe', 'pythonw.exe')):
                python_exe = python_exe.replace('python.exe', 'pythonw.exe')

            if app_path.endswith('.py'):
                command = f'"{python_exe}" "{app_path}"'
            else: # Likely an executable bundled by PyInstaller
                command = f'"{app_path}"'
                
            if enable:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, command)
                logging.info(f"Đã bật 'Chạy cùng Windows' cho '{APP_NAME}'. Command: {command}")
            else:
                try:
                    winreg.DeleteValue(key, APP_NAME)
                    logging.info(f"Đã tắt 'Chạy cùng Windows' cho '{APP_NAME}'.")
                except FileNotFoundError:
                    logging.info(f"'{APP_NAME}' không có trong startup, không cần xóa.")
            winreg.CloseKey(key)
            self.set_setting("run_on_startup", str(enable))
            return True
        except Exception as e:
            logging.error(f"Lỗi khi thay đổi 'Chạy cùng Windows': {e}. Vui lòng thử lại với quyền Admin.")
            return False

    def check_run_on_startup(self):
        """Checks if the application is configured to run on Windows startup."""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_REG_KEY, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, APP_NAME)
            winreg.CloseKey(key)
            app_path = os.path.abspath(sys.argv[0])
            
            if app_path.endswith('.py'):
                expected_command_py = f'"{sys.executable}" "{app_path}"'
                expected_command_pyw = f'"{sys.executable.replace("python.exe", "pythonw.exe")}" "{app_path}"'
                return expected_command_py in value or expected_command_pyw in value
            else:
                return f'"{app_path}"' in value
        except FileNotFoundError:
            return False # Entry not found, so it's not set
        except Exception as e:
            logging.error(f"Lỗi khi kiểm tra 'Chạy cùng Windows': {e}")
            return False


# --- Stealth Manager (New class for stealth features) ---
class StealthManager:
    def __init__(self, settings: SettingsManager, log_signal: pyqtSignal):
        self.settings = settings
        self.log_signal = log_signal
        self.nic_guid = None # Cached GUID of the primary network interface

    def _get_nic_guid_cached(self):
        """Gets and caches the GUID of the active network interface, using preferred iface if set."""
        if not self.nic_guid:
            preferred_iface_name = self.settings.get_setting("preferred_interface_name", "")
            # Get only GUID from the comprehensive network info function
            _, _, _, _, guid, _, _ = get_network_info_via_powershell(preferred_iface_name=preferred_iface_name)
            self.nic_guid = guid
        return self.nic_guid

    def apply_stealth_setting(self, setting_key: str, enable: bool):
        """Applies or reverts a single stealth setting based on the 'enable' flag."""
        # Check if the setting is specific to a network adapter (needs GUID)
        is_network_adapter_specific = setting_key in [
            "stealth_disable_dhcp_hostname_reg"
        ]

        if is_network_adapter_specific:
            nic_guid = self._get_nic_guid_cached()
            if not nic_guid:
                self.log_signal.emit(f"[!] Lỗi: Không tìm thấy card mạng đang hoạt động để áp dụng '{setting_key}'.")
                logging.error(f"Cannot apply '{setting_key}': No active network interface GUID found.")
                return False

        applied = False
        action_desc = "áp dụng" if enable else "khôi phục"
        status_msg = f"Đang {action_desc} thiết lập stealth: {setting_key}..."
        self.log_signal.emit(status_msg)
        logging.info(status_msg)

        try:
            # Firewall rules (netsh advfirewall firewall)
            if setting_key == "stealth_block_icmp":
                rule_name = "[AG] Block Inbound ICMPv4"
                cmd = f"netsh advfirewall firewall { 'add' if enable else 'delete' } rule name=\"{rule_name}\" protocol=icmpv4:8,any dir=in action=block"
                applied, _ = run_powershell_command(cmd, rule_name)
            elif setting_key == "stealth_block_netbios":
                rule_name = "[AG] Block NetBIOS"
                cmd = f"netsh advfirewall firewall { 'add' if enable else 'delete' } rule name=\"{rule_name}\" dir=in action=block protocol=UDP localport=137,138"
                applied, _ = run_powershell_command(cmd, rule_name)
            elif setting_key == "stealth_block_llmnr":
                rule_name = "[AG] Block LLMNR"
                cmd = f"netsh advfirewall firewall { 'add' if enable else 'delete' } rule name=\"{rule_name}\" dir=in action=block protocol=UDP localport=5355"
                applied, _ = run_powershell_command(cmd, rule_name)
            elif setting_key == "stealth_block_mdns":
                rule_name = "[AG] Block mDNS"
                cmd = f"netsh advfirewall firewall { 'add' if enable else 'delete' } rule name=\"{rule_name}\" dir=in action=block protocol=UDP localport=5353"
                applied, _ = run_powershell_command(cmd, rule_name)
            elif setting_key == "stealth_block_rpc_epmap":
                rule_name = "[AG] Block RPC-EPMAP"
                cmd = f"netsh advfirewall firewall { 'add' if enable else 'delete' } rule name=\"{rule_name}\" dir=in action=block protocol=TCP localport=135"
                applied, _ = run_powershell_command(cmd, rule_name)
            elif setting_key == "stealth_block_netbios_ssn":
                rule_name = "[AG] Block NetBIOS-SSN"
                cmd = f"netsh advfirewall firewall { 'add' if enable else 'delete' } rule name=\"{rule_name}\" dir=in action=block protocol=TCP localport=139"
                applied, _ = run_powershell_command(cmd, rule_name)
            elif setting_key == "stealth_block_unknown_5040":
                rule_name = "[AG] Block Unknown-Service-5040"
                cmd = f"netsh advfirewall firewall { 'add' if enable else 'delete' } rule name=\"{rule_name}\" dir=in action=block protocol=TCP localport=5040"
                applied, _ = run_powershell_command(cmd, rule_name)
            elif setting_key == "stealth_block_smb":
                rule_name = "[AG] Block SMB"
                cmd = f"netsh advfirewall firewall { 'add' if enable else 'delete' } rule name=\"{rule_name}\" dir=in action=block protocol=TCP localport=445"
                applied, _ = run_powershell_command(cmd, rule_name)

            # Service management (sc config, sc stop/start)
            elif setting_key == "stealth_disable_ssdp":
                service_name = "SSDPSRV"
                cmd = f"sc config {service_name} start= { 'disabled' if enable else 'auto' }; sc { 'stop' if enable else 'start' } {service_name}"
                applied, _ = run_powershell_command(cmd, f"{'Disable' if enable else 'Enable'} {service_name}")
            elif setting_key == "stealth_disable_upnphost":
                service_name = "upnphost"
                cmd = f"sc config {service_name} start= { 'disabled' if enable else 'auto' }; sc { 'stop' if enable else 'start' } {service_name}"
                applied, _ = run_powershell_command(cmd, f"{'Disable' if enable else 'Enable'} {service_name}")
            elif setting_key == "stealth_disable_fdrespub":
                service_name = "FDResPub"
                cmd = f"sc config {service_name} start= { 'disabled' if enable else 'auto' }; sc { 'stop' if enable else 'start' } {service_name}"
                applied, _ = run_powershell_command(cmd, f"{'Disable' if enable else 'Enable'} {service_name}")
            elif setting_key == "stealth_disable_remote_registry":
                service_name = "RemoteRegistry"
                cmd = f"sc config {service_name} start= { 'disabled' if enable else 'auto' }; sc { 'stop' if enable else 'start' } {service_name}"
                applied, _ = run_powershell_command(cmd, f"{'Disable' if enable else 'Enable'} {service_name}")
            elif setting_key == "stealth_disable_winrm":
                service_name = "WinRM"
                cmd = f"sc config {service_name} start= { 'disabled' if enable else 'auto' }; sc { 'stop' if enable else 'start' } {service_name}"
                applied, _ = run_powershell_command(cmd, f"{'Disable' if enable else 'Enable'} {service_name}")
            elif setting_key == "stealth_disable_rdp": # TermService
                service_name = "TermService"
                cmd = f"sc config {service_name} start= { 'disabled' if enable else 'demand' }; sc { 'stop' if enable else 'start' } {service_name}"
                applied, _ = run_powershell_command(cmd, f"{'Disable' if enable else 'Enable'} {service_name}")
            elif setting_key == "stealth_disable_lanmanserver":
                service_name = "LanmanServer"
                cmd = f"sc config {service_name} start= { 'disabled' if enable else 'auto' }; sc { 'stop' if enable else 'start' } {service_name}"
                applied, _ = run_powershell_command(cmd, f"{'Disable' if enable else 'Enable'} {service_name}")

            # Registry settings
            elif setting_key == "stealth_disable_dhcp_hostname_reg":
                if not nic_guid: return False
                reg_path = f"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{{{nic_guid}}}"
                reg_path_global = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
                
                if enable:
                    cmd1 = f"Set-ItemProperty -Path '{reg_path}' -Name RegisterAdapterName -Value 0 -Force -ErrorAction SilentlyContinue"
                    cmd2 = f"Set-ItemProperty -Path '{reg_path_global}' -Name RegisterName -Value 0 -Force -ErrorAction SilentlyContinue"
                else: # Revert to default by removing the value
                    cmd1 = f"Remove-ItemProperty -Path '{reg_path}' -Name RegisterAdapterName -ErrorAction SilentlyContinue"
                    cmd2 = f"Remove-ItemProperty -Path '{reg_path_global}' -Name RegisterName -ErrorAction SilentlyContinue"
                
                success1, _ = run_powershell_command(cmd1, "Disable DHCP Hostname Reg (Adapter)")
                success2, _ = run_powershell_command(cmd2, "Disable DHCP Hostname Reg (Global)")
                applied = success1 and success2

            # Global TCP/IP settings
            elif setting_key == "stealth_set_ttl_1":
                target_ttl = 1 if enable else 128 # Default Windows TTL is 128 (IPv4)
                cmd = f"netsh int ipv4 set global defaultcurhoplimit={target_ttl}"
                applied, _ = run_powershell_command(cmd, f"Set TTL to {target_ttl}")

            else:
                self.log_signal.emit(f"[!] Thiết lập stealth không xác định: {setting_key}")
                logging.warning(f"Unknown stealth setting key: {setting_key}")
                return False

            if applied:
                self.log_signal.emit(f"[*] Đã {action_desc} thiết lập stealth: {setting_key}.")
                self.settings.set_setting(setting_key, str(enable))
                # Update stealth_has_applied_any flag
                any_applied = any(self.settings.get_setting(k) == "True" for k in self.settings.config if k.startswith("stealth_") and k != "stealth_has_applied_any")
                self.settings.set_setting("stealth_has_applied_any", str(any_applied))
                return True
            else:
                self.log_signal.emit(f"[!] Không thể {action_desc} thiết lập stealth: {setting_key}.")
                logging.error(f"Failed to {action_desc} stealth setting: {setting_key}")
                return False

        except Exception as e:
            self.log_signal.emit(f"[!] Lỗi không xác định khi {action_desc} stealth {setting_key}: {e}")
            logging.error(f"Unknown error applying stealth setting {setting_key}: {e}")
            return False

    def apply_all_stealth_settings(self, initial_load=False):
        """Applies all stored stealth settings. Prioritizes enabling before disabling on initial load."""
        self.log_signal.emit("Đang áp dụng các thiết lập Chế độ tàng hình...")
        self._get_nic_guid_cached() # Pre-fetch NIC GUID for network-specific settings
        
        # Collect all current settings to apply/revert
        settings_to_process = {}
        for key in self.settings.config:
            if key.startswith("stealth_") and key != "stealth_has_applied_any":
                settings_to_process[key] = self.settings.get_setting(key) == "True"

        # Pass 1: Enable all settings that are configured to be True
        for key, enable in settings_to_process.items():
            if enable:
                self.apply_stealth_setting(key, True)
            
        # Pass 2: Disable/revert settings that are configured to be False
        # Only revert if it's not an initial load, or if it's a specific action to ensure state.
        if not initial_load:
            for key, enable in settings_to_process.items():
                if not enable:
                    self.apply_stealth_setting(key, False) # Explicitly revert

        self.log_signal.emit("Đã hoàn tất việc áp dụng thiết lập Chế độ tàng hình.")

    def revert_all_stealth_settings(self):
        """Reverts all stealth settings that were previously applied by the app."""
        self.log_signal.emit("Đang khôi phục tất cả thiết lập Chế độ tàng hình về mặc định...")
        self._get_nic_guid_cached() # Pre-fetch NIC GUID

        for key in self.settings.config:
            if key.startswith("stealth_") and key != "stealth_has_applied_any":
                # Only revert if the setting was ON (True) in the configuration
                # This prevents trying to delete rules/settings we didn't create
                if self.settings.get_setting(key) == "True":
                    self.log_signal.emit(f"Đang khôi phục {key}...")
                    self.apply_stealth_setting(key, False) # Apply False (revert)
                self.settings.set_setting(key, "False") # Always set to False in config after attempting revert
        
        self.settings.set_setting("stealth_has_applied_any", "False")
        self.log_signal.emit("Đã hoàn tất khôi phục thiết lập Chế độ tàng hình.")


# --- ARP Stealth Monitor (QThread for Scapy-based proactive defense) ---
class ARPStealthMonitor(QThread):
    log_signal = pyqtSignal(str)
    
    def __init__(self, my_ip: str, my_mac: str, router_ip: str, router_mac: str, iface: str):
        super().__init__()
        self.my_ip = my_ip
        self.my_mac = my_mac
        self.router_ip = router_ip
        self.router_mac = router_mac
        self.iface = iface # Scapy-specific interface name (e.g., '\Device\NPF_{GUID}')
        self._is_running = True
        self.sniff_thread = None
        
    def stop(self):
        """Signals the monitoring thread to stop and waits for it to finish."""
        self._is_running = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            logging.info("Signaling ARP Stealth sniff thread to stop.")
        self.quit()
        self.wait(2000) # Wait up to 2 seconds for the thread to finish cleanly

    def run(self):
        """Main execution loop for the ARP Stealth monitor thread."""
        if not _has_scapy:
            self.log_signal.emit("[!] ARP Stealth bị TẮT: Không tìm thấy Scapy hoặc Npcap.")
            logging.error("ARP Stealth disabled: Scapy or Npcap not found.")
            return

        self.log_signal.emit(f"Bắt đầu ARP Stealth trên giao diện: '{self.iface}'")
        self.log_signal.emit(f"Chủ động bảo vệ: Máy ({self.my_ip}, {self.my_mac}) khỏi Router ({self.router_ip}, {self.router_mac}).")

        try:
            conf.iface = self.iface
            conf.verb = 0 # Suppress Scapy verbose output
            
            # Nested function for the actual sniffing loop to run in a separate thread
            def _sniff_target():
                try:
                    while self._is_running:
                        # Use timeout to allow periodic checking of _is_running
                        sniff(filter="arp", prn=self._arp_filter_callback, store=0, 
                              iface=self.iface, timeout=1) # Sniff for 1 second, then re-check _is_running
                except Exception as e:
                    self.log_signal.emit(f"[!] Lỗi khi sniff ARP cho Stealth: {e}")
                    logging.error(f"Error during ARP sniff in stealth mode: {e}")
            
            # Start the sniffing in a non-GUI blocking thread
            import threading
            self.sniff_thread = threading.Thread(target=_sniff_target, daemon=True)
            self.sniff_thread.start()

            # QThread's event loop to handle signals
            self.exec_()

        except Exception as e:
            self.log_signal.emit(f"[!] Lỗi khởi tạo ARP Stealth: {e}")
            logging.error(f"Error initializing ARP Stealth: {e}")

    def _arp_filter_callback(self, pkt):
        """Callback function for incoming ARP packets."""
        if not self._is_running: # Ensure we stop processing if thread is terminating
            return

        try:
            if pkt.haslayer(ARP) and pkt[ARP].op == 1: # ARP request
                # Check if the request is for OUR IP address
                if pkt[ARP].pdst == self.my_ip:
                    sender_ip = pkt[ARP].psrc
                    sender_mac = pkt[ARP].hwsrc

                    # IMPORTANT: Only reply if the sender is OUR router AND its MAC matches
                    if sender_ip == self.router_ip and sender_mac.lower() == self.router_mac.lower():
                        # Construct a legitimate ARP reply
                        arp_reply = ARP(
                            op=2, # ARP reply
                            hwsrc=self.my_mac, # Our MAC
                            psrc=self.my_ip, # Our IP
                            hwdst=sender_mac, # Destination MAC (requester's MAC)
                            pdst=sender_ip # Destination IP (requester's IP)
                        )
                        # Send the reply
                        send(arp_reply, verbose=0, iface=self.iface)
                        logging.debug(f"[*] ARP Stealth: Replied to legitimate ARP request from {sender_ip} ({sender_mac}).")
                    else:
                        # Log if an ARP request for our IP comes from an unexpected source
                        logging.warning(f"[!] ARP Stealth: Chặn yêu cầu ARP từ nguồn không xác định: {sender_ip} ({sender_mac}) muốn biết MAC của {pkt[ARP].pdst}. (Yêu cầu chỉ trả lời router của bạn).")
                        # Do NOT send a reply if it's not the router
        except Exception as e:
            logging.error(f"Lỗi trong arp_filter_callback: {e}")
            self.log_signal.emit(f"[!] Lỗi trong ARP Stealth filter: {e}")


# --- Core Logic: ARP Management ---
class ARPManager(QThread):
    status_signal = pyqtSignal(str, str, str) # status_text, gateway_ip, gateway_mac
    log_signal = pyqtSignal(str)
    force_lock_signal = pyqtSignal()
    update_interval_signal = pyqtSignal(int)
    setting_changed_signal = pyqtSignal(str, bool) 

    def __init__(self, settings: SettingsManager):
        super().__init__()
        self.settings = settings
        self._is_running = True
        # Store comprehensive network info here
        self.net_info = { 
            "gateway_ip": None, "host_ip": None, "host_mac": None, 
            "adapter_name": None, "adapter_guid": None, "ifindex": None, 
            "network_id": None, # ProfileGuid
            "gateway_mac": None # NEW: Store gateway's actual MAC
        }
        self.scapy_iface_name = None # Scapy's internal interface name
        self.timer = None
        self.consecutive_no_network = 0 # Counter for consecutive checks with no network/gateway
        self._is_auto_lock_enabled_cached = self.settings.get_setting("auto_lock_enabled") == "True"
        self._is_locked_successfully = False # Flag indicating if current_gateway is successfully locked
        self._last_logged_status = "" 
        self._periodic_check_interval = int(self.settings.get_setting("periodic_check_interval", "5")) * 1000
        
        self.arp_stealth_monitor = None
        self.stealth_manager = StealthManager(settings, self.log_signal)

    def stop(self):
        self._is_running = False
        if self.timer and self.timer.isActive():
            self.timer.stop()
            logging.info("ARPManager periodic timer stopped.")
        if self.arp_stealth_monitor:
            self.arp_stealth_monitor.stop()
            self.arp_stealth_monitor = None
            logging.info("ARP Stealth monitor stopped.")
        
        # Revert stealth settings if they were applied by the app on shutdown
        if self.settings.get_setting("stealth_has_applied_any") == "True":
            self.stealth_manager.revert_all_stealth_settings()

        self.quit()
        self.wait(5000) # Wait up to 5 seconds for the thread to terminate

    def run(self):
        self.force_lock_signal.connect(self._on_force_lock_requested)
        self.update_interval_signal.connect(self.set_periodic_check_interval)
        
        self.log_signal.emit("Bắt đầu kiểm tra mạng và ARP...")
        self.stealth_manager.apply_all_stealth_settings(initial_load=True)
        self.periodic_check() 

        self.timer = QTimer()
        self.timer.setInterval(self._periodic_check_interval)
        self.timer.timeout.connect(self.periodic_check)
        self.timer.start()
        logging.info(f"ARPManager periodic check started with interval {self._periodic_check_interval / 1000} seconds.")

        self.exec_()

    def set_periodic_check_interval(self, interval_seconds: int):
        self._periodic_check_interval = interval_seconds * 1000
        if self.timer:
            self.timer.setInterval(self._periodic_check_interval)
            logging.info(f"Đã cập nhật khoảng thời gian kiểm tra định kỳ thành {interval_seconds} giây.")
            self.log_signal.emit(f"Đã cập nhật khoảng thời gian kiểm tra định kỳ thành {interval_seconds} giây.")
        self.settings.set_setting("periodic_check_interval", str(interval_seconds))

    def _get_current_network_info(self) -> bool:
        """
        Retrieves all relevant network information using PowerShell.
        Populates self.net_info and self.scapy_iface_name.
        Returns True if essential info (gateway_ip, host_ip, host_mac, adapter_name) is found.
        """
        preferred_iface_name = self.settings.get_setting("preferred_interface_name", "")
        
        (gateway_ip, host_ip, host_mac, adapter_name, 
         adapter_guid, ifindex, network_id) = get_network_info_for_adapter(preferred_iface_name=preferred_iface_name)
        
        # Update net_info dictionary
        self.net_info.update({
            "gateway_ip": gateway_ip, "host_ip": host_ip, "host_mac": host_mac,
            "adapter_name": adapter_name, "adapter_guid": adapter_guid, "ifindex": ifindex,
            "network_id": network_id
        })

        if not (gateway_ip and host_ip and host_mac and adapter_name):
            logging.warning("Không thể lấy đầy đủ thông tin mạng cần thiết.")
            return False
        
        # Determine Scapy interface name for ARP Stealth (requires host_mac for matching)
        self.scapy_iface_name = None
        if _has_scapy:
            conf.verb = 0
            try:
                working_interfaces = get_working_if() # (scapy_name, friendly_name, description)
                for scapy_name, friendly_name_scapy, description_scapy in working_interfaces:
                    # Match Scapy's interface by its reported MAC address, which is reliable
                    # Fallback to name/description if MAC doesn't match for some reason
                    if host_mac.lower() == get_if_hwaddr(scapy_name).lower():
                        self.scapy_iface_name = scapy_name
                        logging.debug(f"Đã khớp Scapy interface '{self.scapy_iface_name}' qua MAC của máy ({host_mac}).")
                        break
                    elif adapter_name.lower() == friendly_name_scapy.lower() or \
                         adapter_name.lower() in description_scapy.lower():
                        self.scapy_iface_name = scapy_name
                        logging.debug(f"Đã khớp Scapy interface '{self.scapy_iface_name}' qua tên adapter '{adapter_name}'.")
                        break

                if not self.scapy_iface_name:
                    logging.warning(f"Không tìm thấy Scapy interface cho adapter '{adapter_name}'. ARP Stealth có thể không hoạt động.")
            except Exception as e:
                logging.error(f"Lỗi khi lấy danh sách giao diện Scapy: {e}. ARP Stealth bị ảnh hưởng.")

        return True


    def periodic_check(self):
        """
        Main periodic check function.
        Handles network state changes, ARP locking, and ARP Stealth management.
        Improved no-network handling and uses consistent PowerShell info retrieval.
        """
        # --- Handle auto_lock_enabled status change logging and sync ---
        current_auto_lock_status = self.settings.get_setting("auto_lock_enabled") == "True"
        if current_auto_lock_status != self._is_auto_lock_enabled_cached:
            self._is_auto_lock_enabled_cached = current_auto_lock_status
            if not current_auto_lock_status:
                self.log_signal.emit("Chức năng khóa ARP tự động đã TẮT.")
                self.status_signal.emit("Tắt", "N/A", "N/A")
                self._is_locked_successfully = False 
                if self.arp_stealth_monitor:
                    self.arp_stealth_monitor.stop()
                    self.arp_stealth_monitor = None
                    self.log_signal.emit("Đã dừng ARP Stealth.")
            else:
                self.log_signal.emit("Chức năng khóa ARP tự động đã BẬT. Đang kiểm tra trạng thái mạng...")
            self.setting_changed_signal.emit("auto_lock_enabled", current_auto_lock_status)
            
        if not current_auto_lock_status:
            return # If auto-lock is off, do nothing further

        # --- Get current network info ---
        # This will try to use preferred interface if set, and fallback to auto-detect
        found_network_info = self._get_current_network_info() # Populates self.net_info and self.scapy_iface_name

        # --- Scenario 1: No active network connection detected ---
        if not found_network_info:
            self.consecutive_no_network += 1
            if self.consecutive_no_network >= 3: # Wait for 3 consecutive checks to confirm no network
                if self._last_logged_status != "Không có mạng": # Only log once after confirmation
                    self.log_signal.emit(f"Mất kết nối mạng hoặc không tìm thấy gateway/IP sau {self.consecutive_no_network} lần kiểm tra. Đang reset ARP cũ (nếu có)...")
                    if self.net_info.get("gateway_ip"): 
                        reset_arp_to_default(self.net_info.get("gateway_ip"))
                    # Reset all stored network info
                    self.net_info = { 
                        "gateway_ip": None, "host_ip": None, "host_mac": None, 
                        "adapter_name": None, "adapter_guid": None, "ifindex": None, 
                        "network_id": None, "gateway_mac": None
                    }
                    self.scapy_iface_name = None
                    self._is_locked_successfully = False
                    # Stop ARP Stealth if it was running
                    if self.arp_stealth_monitor:
                        self.arp_stealth_monitor.stop()
                        self.arp_stealth_monitor = None
                        self.log_signal.emit("Đã dừng ARP Stealth do mất mạng.")
                    self.status_signal.emit("Không có mạng", "N/A", "N/A")
                    self._last_logged_status = "Không có mạng"
            elif self.consecutive_no_network == 1:
                 self.log_signal.emit("Không tìm thấy Gateway hoặc ID mạng. Đang chờ kết nối mạng...")
                 self.status_signal.emit("Chờ mạng", "N/A", "N/A")
            return # Exit, will re-check on next timer interval
        else:
            # Network re-established or found
            if self.consecutive_no_network > 0:
                self.log_signal.emit(f"Đã tìm thấy lại mạng ({self.net_info['gateway_ip']}). Đang tiếp tục kiểm tra...")
            self.consecutive_no_network = 0 # Reset counter if network is found

        # --- Determine if a re-lock is needed (Network change, Gateway change, or not successfully locked) ---
        # Get last persisted info for comparison
        last_locked_gateway = self.settings.get_setting("last_locked_gateway", "")
        last_locked_mac = self.settings.get_setting("last_locked_mac", "") # Gateway's MAC from last lock
        last_network_id = self.settings.get_setting("last_network_id", "") # ProfileGuid from last lock
        last_host_ip = self.settings.get_setting("last_host_ip", "") # Host's IP from last lock
        last_adapter_name = self.settings.get_setting("last_adapter_name", "") # Adapter name from last lock

        # Check if any significant network parameter has changed
        network_changed_flag = False
        reasons = []

        # Compare current values in self.net_info with persisted 'last_...' settings
        # Note: self.net_info['gateway_mac'] holds the *gateway's* MAC once known, NOT host's MAC
        # self.net_info['host_mac'] holds *our* (host's) MAC
        
        # Reason 1: Network ID changed (most robust indicator of network change)
        if self.net_info['network_id'] is None or last_network_id == "" or self.net_info['network_id'] != last_network_id:
            network_changed_flag = True
            reasons.append(f"Mạng thay đổi (ID: '{last_network_id}' -> '{self.net_info['network_id']}')")
        
        # Reason 2: Gateway IP changed
        if self.net_info['gateway_ip'] is None or last_locked_gateway == "" or self.net_info['gateway_ip'] != last_locked_gateway:
            network_changed_flag = True
            reasons.append(f"Gateway IP thay đổi (từ '{last_locked_gateway}' -> '{self.net_info['gateway_ip']}')")
        
        # Reason 3: Host's IP changed
        if self.net_info['host_ip'] is None or last_host_ip == "" or self.net_info['host_ip'] != last_host_ip:
            network_changed_flag = True
            reasons.append(f"IP của máy thay đổi (từ '{last_host_ip}' -> '{self.net_info['host_ip']}')")
            
        # Reason 4: Adapter Name changed (implying a different physical/virtual adapter became primary)
        if self.net_info['adapter_name'] is None or last_adapter_name == "" or self.net_info['adapter_name'] != last_adapter_name:
            network_changed_flag = True
            reasons.append(f"Card mạng chính thay đổi (từ '{last_adapter_name}' -> '{self.net_info['adapter_name']}')")
        
        # Reason 5: If the gateway's MAC (last_locked_mac) does not match the currently discovered MAC (net_info['gateway_mac'])
        # This will be checked in perform_arp_lock after gateway_mac is discovered.
        # But for triggering re-lock if already locked but MAC changes unexpectedly.
        # This is a critical check for ARP spoofing detection.
        if self._is_locked_successfully and last_locked_mac and self.net_info['gateway_mac'] and last_locked_mac != self.net_info['gateway_mac']:
             network_changed_flag = True # This indicates a possible ARP spoofing or router MAC change
             reasons.append(f"MAC của Gateway thay đổi bất thường (từ '{last_locked_mac}' -> '{self.net_info['gateway_mac']}').")

        # If any significant change occurred OR we are not successfully locked, attempt a re-lock.
        if network_changed_flag or not self._is_locked_successfully:
            self.log_signal.emit(f"Yêu cầu khóa lại ARP: {'; '.join(reasons) if reasons else 'Chưa khóa thành công trước đó'}.")
            
            # --- Prepare for a new lock attempt ---
            if self.arp_stealth_monitor:
                self.arp_stealth_monitor.stop()
                self.arp_stealth_monitor = None
                self.log_signal.emit("Đã dừng ARP Stealth để chuẩn bị khóa ARP mới.")

            # Always try to reset previous ARP if a gateway was known from last check
            if last_locked_gateway: # Use the *persisted* last gateway to try and delete its entry
                reset_arp_to_default(last_locked_gateway)
                self.log_signal.emit(f"Đã reset ARP cho {last_locked_gateway} về mặc định.")
            
            # Perform the lock for the current network info
            self.perform_arp_lock(self.net_info['gateway_ip']) # Calls get_mac_from_arp_powershell internally
            return # Exit, will re-check on next timer interval

        # --- Scenario: Stable state (locked, all relevant network info unchanged) ---
        if self._is_locked_successfully: # If already locked and no re-lock needed by above flags
            if self._last_logged_status != "Đã khóa":
                self.status_signal.emit("Đã khóa", self.net_info['gateway_ip'], self.net_info['gateway_mac'])
                self._last_logged_status = "Đã khóa"
            
            current_stealth_setting = self.settings.get_setting("arp_stealth_enabled") == "True"
            self.setting_changed_signal.emit("arp_stealth_enabled", current_stealth_setting)

            if current_stealth_setting and _has_scapy and not self.arp_stealth_monitor:
                if is_admin():
                    if self.net_info['host_ip'] and self.net_info['host_mac'] and \
                       self.scapy_iface_name and self.net_info['gateway_ip'] and self.net_info['gateway_mac']:
                        
                        self.arp_stealth_monitor = ARPStealthMonitor(
                            self.net_info['host_ip'], self.net_info['host_mac'], # My PC's info
                            self.net_info['gateway_ip'], self.net_info['gateway_mac'], # Router's info
                            self.scapy_iface_name
                        )
                        self.arp_stealth_monitor.log_signal.connect(self.log_signal)
                        self.arp_stealth_monitor.start()
                    else:
                        self.log_signal.emit("[!] Không thể khởi động ARP Stealth: Thiếu thông tin IP/MAC của máy hoặc giao diện Scapy.")
                        logging.error("Missing critical info for ARP Stealth startup in stable state.")
                else:
                    self.log_signal.emit("[!] Không thể khởi động ARP Stealth: Yêu cầu quyền quản trị (Administrator).")
                    logging.warning("Admin rights required to start ARP Stealth.")
            elif not current_stealth_setting and self.arp_stealth_monitor:
                self.arp_stealth_monitor.stop()
                self.arp_stealth_monitor = None
                self.log_signal.emit("Đã dừng ARP Stealth do cài đặt bị tắt.")
                logging.info("ARP Stealth stopped due to settings change.")
            return

        # Fallback for unexpected states (should ideally not be hit often)
        logging.warning(f"ARPManager ở trạng thái không xác định. Đã bỏ qua kiểm tra.")
        self.status_signal.emit("Kiểm tra lại", "N/A", "N/A")


    def perform_arp_lock(self, gateway_ip: str):
        """
        Attempts to lock the ARP entry for the given gateway IP using its MAC.
        Retrieves MAC via PowerShell for robustness.
        """
        if not gateway_ip:
            self.log_signal.emit("[!] Lỗi: Không có Gateway IP để thực hiện khóa ARP.")
            self.status_signal.emit("Lỗi Thao Tác", "N/A", "N/A")
            self._is_locked_successfully = False
            self._last_logged_status = "Lỗi Thao Tác"
            return

        # Use the robust PowerShell-based MAC retrieval
        gateway_mac = get_mac_from_arp_powershell(gateway_ip) 
        if gateway_mac:
            if set_static_arp(gateway_ip, gateway_mac):
                # Update stored network info after successful lock
                self.net_info["gateway_ip"] = gateway_ip
                self.net_info["gateway_mac"] = gateway_mac # Store gateway's actual MAC
                # host_mac is already in self.net_info from _get_current_network_info

                self._is_locked_successfully = True
                self._last_logged_status = "Đã khóa"

                # Persist the info of the CURRENTLY LOCKED network
                self.settings.set_setting("last_locked_gateway", gateway_ip)
                self.settings.set_setting("last_locked_mac", gateway_mac) # Store gateway's MAC
                self.settings.set_setting("last_network_id", self.net_info['network_id'])
                self.settings.set_setting("last_host_ip", self.net_info['host_ip'])
                self.settings.set_setting("last_adapter_name", self.net_info['adapter_name'])

                self.log_signal.emit(f"[*] Đã khóa ARP thành công: {gateway_ip} → {gateway_mac}")
                self.status_signal.emit("Đã khóa", gateway_ip, gateway_mac)

                # Trigger ARP Stealth if enabled (will check conditions internally)
                current_stealth_setting = self.settings.get_setting("arp_stealth_enabled") == "True"
                self.setting_changed_signal.emit("arp_stealth_enabled", current_stealth_setting)

                if current_stealth_setting and _has_scapy and not self.arp_stealth_monitor:
                    if is_admin():
                        if self.net_info['host_ip'] and self.net_info['host_mac'] and \
                           self.scapy_iface_name and self.net_info['gateway_ip'] and self.net_info['gateway_mac']:
                            self.arp_stealth_monitor = ARPStealthMonitor(
                                self.net_info['host_ip'], self.net_info['host_mac'], 
                                self.net_info['gateway_ip'], self.net_info['gateway_mac'], 
                                self.scapy_iface_name
                            )
                            self.arp_stealth_monitor.log_signal.connect(self.log_signal)
                            self.arp_stealth_monitor.start()
                        else:
                            self.log_signal.emit("[!] Không thể khởi động ARP Stealth: Thiếu thông tin IP/MAC của máy hoặc giao diện Scapy (sau khi khóa).")
                            logging.error("Missing critical info for ARP Stealth startup during lock.")
                    else:
                        self.log_signal.emit("[!] Không thể khởi động ARP Stealth: Yêu cầu quyền quản trị (Administrator).")
                        logging.warning("Admin rights required to start ARP Stealth.")

            else:
                self.log_signal.emit(f"[!] Lỗi khi khóa ARP cho {gateway_ip}. Vui lòng đảm bảo chương trình chạy với quyền Admin.")
                self.status_signal.emit("Lỗi Khóa", gateway_ip, "N/A")
                self._is_locked_successfully = False
                self._last_logged_status = "Lỗi Khóa"
                if self.arp_stealth_monitor:
                    self.arp_stealth_monitor.stop()
                    self.arp_stealth_monitor = None
                    self.log_signal.emit("Đã dừng ARP Stealth do khóa ARP thất bại.")
        else:
            self.log_signal.emit(f"[!] Không thể lấy MAC của gateway {gateway_ip}. Không thể khóa ARP.")
            self.status_signal.emit("Lỗi MAC", gateway_ip, "N/A")
            # Clear relevant parts of net_info if MAC acquisition fails
            self.net_info["gateway_ip"] = gateway_ip # Keep gateway IP for display
            self.net_info["gateway_mac"] = None # Indicate MAC not found
            self._is_locked_successfully = False
            self._last_logged_status = "Lỗi MAC"
            if self.arp_stealth_monitor:
                self.arp_stealth_monitor.stop()
                self.arp_stealth_monitor = None
                self.log_signal.emit("Đã dừng ARP Stealth do không tìm thấy MAC Gateway.")

    def _on_force_lock_requested(self):
        logging.info("Yêu cầu khóa ARP thủ công được tiếp nhận bởi ARPManager.")
        
        # Clear previous state to force a full re-evaluation and lock attempt
        self._is_locked_successfully = False
        self.net_info = { # Reset to force full re-detection
            "gateway_ip": None, "host_ip": None, "host_mac": None, 
            "adapter_name": None, "adapter_guid": None, "ifindex": None, 
            "network_id": None, "gateway_mac": None
        }
        self.scapy_iface_name = None # Also reset Scapy iface
        self.log_signal.emit("Đang thực hiện khóa ARP thủ công...")
        self.periodic_check() # Trigger an immediate check

# --- Settings Dialog (New Window) ---
class SettingsDialog(QDialog):
    def __init__(self, settings: SettingsManager, arp_manager: ARPManager, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.arp_manager = arp_manager
        self.setWindowTitle("Thiết lập Nâng cao")
        self.setMinimumSize(450, 600)
        self.init_ui()
        self.load_settings()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        
        tab_widget = QTabWidget(self)
        main_layout.addWidget(tab_widget)

        # --- General Settings Tab ---
        general_tab = QWidget()
        general_layout = QFormLayout(general_tab)
        
        self.interval_spinbox = QSpinBox(self)
        self.interval_spinbox.setRange(1, 60)
        self.interval_spinbox.setSuffix(" giây")
        general_layout.addRow("Khoảng thời gian kiểm tra ARP:", self.interval_spinbox)

        # New: Preferred Network Adapter selection
        self.preferred_adapter_combo = QComboBox(self)
        # Populate this in load_settings based on live adapter list
        general_layout.addRow("Chọn Card mạng chính:", self.preferred_adapter_combo)
        
        tab_widget.addTab(general_tab, "Chung")

        # --- Stealth Settings Tab ---
        stealth_tab = QWidget()
        stealth_scroll_area = QScrollArea(stealth_tab)
        stealth_scroll_area.setWidgetResizable(True)
        stealth_content_widget = QWidget(stealth_scroll_area)
        stealth_layout = QVBoxLayout(stealth_content_widget)
        stealth_layout.setAlignment(Qt.AlignTop | Qt.AlignLeft)

        self.stealth_checkboxes = {}

        stealth_options = {
            "Firewall Rules": {
                "stealth_block_icmp": "Chặn Ping (ICMPv4)",
                "stealth_block_netbios": "Chặn NetBIOS (UDP 137, 138)",
                "stealth_block_llmnr": "Chặn LLMNR (UDP 5355)",
                "stealth_block_mdns": "Chặn mDNS (UDP 5353)",
                "stealth_block_rpc_epmap": "Chặn RPC Endpoint Mapper (TCP 135)",
                "stealth_block_netbios_ssn": "Chặn NetBIOS Session (TCP 139)",
                "stealth_block_unknown_5040": "Chặn dịch vụ không xác định (TCP 5040)",
                "stealth_block_smb": "Chặn SMB (TCP 445 - Chia sẻ file)",
            },
            "Windows Services": {
                "stealth_disable_ssdp": "Tắt dịch vụ SSDP (Discovery)",
                "stealth_disable_upnphost": "Tắt dịch vụ UPnP Host",
                "stealth_disable_fdrespub": "Tắt dịch vụ FDResPub",
                "stealth_disable_remote_registry": "Vô hiệu hóa Remote Registry",
                "stealth_disable_winrm": "Vô hiệu hóa WinRM (Quản lý từ xa)",
                "stealth_disable_rdp": "Vô hiệu hóa Remote Desktop (RDP)",
                "stealth_disable_lanmanserver": "Tắt dịch vụ chia sẻ File/Printer",
            },
            "Other Settings": {
                "stealth_disable_dhcp_hostname_reg": "Vô hiệu hóa đăng ký Hostname với DHCP",
                "stealth_set_ttl_1": "Đặt TTL mặc định về 1 (Giảm phạm vi quét)"
            }
        }

        for category, options in stealth_options.items():
            group_box = QGroupBox(category)
            group_layout = QVBoxLayout(group_box)
            for key, text in options.items():
                checkbox = QCheckBox(text, group_box)
                group_layout.addWidget(checkbox)
                self.stealth_checkboxes[key] = checkbox
            stealth_layout.addWidget(group_box)
        
        stealth_layout.addStretch(1)

        stealth_content_widget.setLayout(stealth_layout)
        stealth_scroll_area.setWidget(stealth_content_widget) # Fixed variable name here
        
        stealth_tab_layout = QVBoxLayout(stealth_tab)
        stealth_tab_layout.addWidget(stealth_scroll_area)

        stealth_note = QLabel("<i>Lưu ý: Các thiết lập này yêu cầu quyền quản trị (Administrator) để hoạt động. Một số thay đổi có thể cần khởi động lại.</i>")
        stealth_note.setStyleSheet("color: #AAAAAA;")
        stealth_note.setWordWrap(True)
        stealth_tab_layout.addWidget(stealth_note)

        tab_widget.addTab(stealth_tab, "Chế độ tàng hình")

        button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.RestoreDefaults | QDialogButtonBox.Cancel, self)
        button_box.button(QDialogButtonBox.Save).setText("Lưu & Áp dụng")
        button_box.button(QDialogButtonBox.RestoreDefaults).setText("Khôi phục mặc định")
        button_box.button(QDialogButtonBox.Cancel).setText("Hủy")

        button_box.accepted.connect(self.save_and_apply)
        button_box.rejected.connect(self.reject)
        button_box.button(QDialogButtonBox.RestoreDefaults).clicked.connect(self.restore_stealth_defaults)
        
        main_layout.addWidget(button_box)

    def load_settings(self):
        interval = int(self.settings.get_setting("periodic_check_interval", "5"))
        self.interval_spinbox.setValue(interval)

        # Populate adapter combobox
        adapters = list_all_network_adapters()
        self.preferred_adapter_combo.clear()
        self.preferred_adapter_combo.addItem("Tự động (Khuyên dùng nếu không có lỗi)") # Default option
        self.preferred_adapter_combo.setItemData(0, "", Qt.UserRole) # Store empty string as data for auto-detect

        current_preferred_name = self.settings.get_setting("preferred_interface_name", "")
        current_index_in_combo = 0 # Default to "Auto"
        
        for i, adapter in enumerate(adapters):
            display_text = f"{adapter['name']} ({adapter['description']}) - {adapter['status']}"
            if adapter['status'] == "Up":
                display_text += " (Đang hoạt động)"
            elif adapter['status'] == "Disconnected":
                display_text += " (Ngắt kết nối)"
            
            self.preferred_adapter_combo.addItem(display_text)
            self.preferred_adapter_combo.setItemData(self.preferred_adapter_combo.count() - 1, adapter['name'], Qt.UserRole)
            if adapter['name'] == current_preferred_name:
                current_index_in_combo = self.preferred_adapter_combo.count() - 1
        
        self.preferred_adapter_combo.setCurrentIndex(current_index_in_combo)

        # Load stealth settings
        for key, checkbox in self.stealth_checkboxes.items():
            checkbox.setChecked(self.settings.get_setting(key) == "True")
            if not is_admin():
                checkbox.setEnabled(False)
                checkbox.setText(checkbox.text() + " (Chỉ Admin)")
                checkbox.setStyleSheet("color: #888888;")

    def save_and_apply(self):
        if not is_admin():
            QMessageBox.critical(self, "Lỗi Quyền Admin", "Vui lòng chạy chương trình với quyền quản trị để lưu và áp dụng thiết lập nâng cao.")
            return

        # Save general settings
        new_interval = self.interval_spinbox.value()
        if new_interval != int(self.settings.get_setting("periodic_check_interval", "5")):
            self.arp_manager.update_interval_signal.emit(new_interval) 
            logging.info(f"Đã cập nhật thiết lập: Khoảng thời gian kiểm tra {new_interval} giây.")

        selected_adapter_name = self.preferred_adapter_combo.currentData(Qt.UserRole)
        current_stored_adapter = self.settings.get_setting("preferred_interface_name", "")
        if selected_adapter_name != current_stored_adapter:
            self.settings.set_setting("preferred_interface_name", selected_adapter_name)
            self.arp_manager.log_signal.emit(f"Đã cập nhật card mạng ưu tiên: '{selected_adapter_name if selected_adapter_name else 'Tự động'}'.")
            # Force a re-check and potential re-lock due to adapter change
            # Reset last network info so it's fully re-detected using the new preferred adapter
            self.settings.set_setting("last_locked_gateway", "")
            self.settings.set_setting("last_locked_mac", "")
            self.settings.set_setting("last_network_id", "")
            self.settings.set_setting("last_host_ip", "")
            self.settings.set_setting("last_adapter_name", "")
            self.arp_manager._is_locked_successfully = False # Force re-lock
            # Immediately trigger a check to use the new preferred adapter
            QTimer.singleShot(100, self.arp_manager.periodic_check)


        # Save and apply stealth settings
        self.arp_manager.log_signal.emit("Đang lưu và áp dụng thiết lập Chế độ tàng hình...")
        for key, checkbox in self.stealth_checkboxes.items():
            current_state = self.settings.get_setting(key) == "True"
            new_state = checkbox.isChecked()
            if new_state != current_state:
                self.arp_manager.stealth_manager.apply_stealth_setting(key, new_state)
            else:
                self.settings.set_setting(key, str(new_state))

        self.arp_manager.log_signal.emit("Đã hoàn tất việc lưu và áp dụng thiết lập Chế độ tàng hình.")
        self.accept()

    def restore_stealth_defaults(self):
        reply = QMessageBox.question(self, 'Xác nhận Khôi phục',
                                     "Bạn có chắc chắn muốn khôi phục tất cả thiết lập Chế độ tàng hình về mặc định không?\n"
                                     "Thao tác này sẽ VÔ HIỆU HÓA tất cả các tính năng tàng hình và có thể yêu cầu khởi động lại.",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            if not is_admin():
                QMessageBox.critical(self, "Lỗi Quyền Admin", "Vui lòng chạy chương trình với quyền quản trị để khôi phục thiết lập.")
                return

            self.arp_manager.stealth_manager.revert_all_stealth_settings()
            for key, checkbox in self.stealth_checkboxes.items():
                checkbox.setChecked(False)
            self.arp_manager.log_signal.emit("Đã khôi phục các thiết lập Chế độ tàng hình về mặc định.")
            self.accept()

# --- GUI Components ---
class MainWindow(QMainWindow):
    def __init__(self, arp_manager: ARPManager, settings: SettingsManager, parent=None):
        super().__init__(parent)
        self.arp_manager = arp_manager
        self.settings = settings
        self.tray_icon_ref = None
        self.init_ui()
        self.load_initial_state()
        self.connect_signals()

    def init_ui(self):
        self.setWindowTitle(f"{APP_NAME} - {APP_VERSION}")
        self.setWindowIcon(QIcon(ICON_FILE))
        self.setGeometry(100, 100, 650, 750)
        self.setMinimumSize(450, 550)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        status_group = QGroupBox("Trạng thái Khóa ARP")
        status_layout = QVBoxLayout()
        self.status_label = QLabel("Đang chờ...")
        self.status_label.setFont(QFont("Segoe UI", 16, QFont.Bold))
        self.status_label.setStyleSheet("color: #FFFFFF;")
        self.status_label.setWordWrap(True)
        status_layout.addWidget(self.status_label)
        self.gateway_label = QLabel("Gateway: N/A")
        self.mac_label = QLabel("MAC: N/A")
        status_layout.addWidget(self.gateway_label)
        status_layout.addWidget(self.mac_label)
        status_group.setLayout(status_layout)
        main_layout.addWidget(status_group)

        control_group = QGroupBox("Tùy chỉnh")
        control_layout = QVBoxLayout()
        
        self.auto_lock_checkbox = QCheckBox("Tự động khóa ARP khi thay đổi mạng")
        self.auto_lock_checkbox.stateChanged.connect(self.on_auto_lock_checkbox_changed)
        control_layout.addWidget(self.auto_lock_checkbox)
        
        self.run_on_startup_checkbox = QCheckBox("Chạy cùng Windows")
        self.run_on_startup_checkbox.stateChanged.connect(self.on_run_on_startup_checkbox_changed)
        control_layout.addWidget(self.run_on_startup_checkbox)
        
        if _has_scapy:
            self.arp_stealth_checkbox = QCheckBox("Bật bảo vệ ARP chủ động (Yêu cầu Npcap)")
            self.arp_stealth_checkbox.stateChanged.connect(self.on_arp_stealth_checkbox_changed)
            control_layout.addWidget(self.arp_stealth_checkbox)
        else:
            self.arp_stealth_checkbox = QLabel("Bảo vệ ARP chủ động (Không khả dụng - Cần Scapy & Npcap đã cài đặt)")
            self.arp_stealth_checkbox.setStyleSheet("color: #888888;")
            control_layout.addWidget(self.arp_stealth_checkbox)

        control_group.setLayout(control_layout)
        main_layout.addWidget(control_group)

        manual_group = QGroupBox("Thao tác thủ công")
        manual_layout = QVBoxLayout()
        manual_buttons_layout = QHBoxLayout()
        
        self.force_lock_button = QPushButton("Khóa ARP Ngay lập tức")
        self.force_lock_button.clicked.connect(self.force_lock_arp)
        self.force_lock_button.setMinimumHeight(45)
        self.force_lock_button.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.reset_arp_button = QPushButton("Reset ARP về mặc định") 
        self.reset_arp_button.clicked.connect(self.reset_arp_to_default_manual)
        self.reset_arp_button.setMinimumHeight(45)
        self.reset_arp_button.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Expanding)

        manual_buttons_layout.addWidget(self.force_lock_button)
        manual_buttons_layout.addWidget(self.reset_arp_button)
        manual_layout.addLayout(manual_buttons_layout)
        manual_group.setLayout(manual_layout)
        main_layout.addWidget(manual_group)

        log_group = QGroupBox("Lịch sử hoạt động")
        log_layout = QVBoxLayout()
        self.log_text_edit = QTextEdit()
        self.log_text_edit.setReadOnly(True)
        self.log_text_edit.setFont(QFont("Consolas", 9))
        self.log_text_edit.setText("Chờ đợi cập nhật log...")
        log_layout.addWidget(self.log_text_edit)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group, 1)

        bottom_buttons_layout = QHBoxLayout()
        
        self.about_button = QPushButton("Về " + APP_NAME)
        self.about_button.clicked.connect(self.show_about_dialog)
        self.about_button.setMinimumHeight(45)
        self.about_button.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Expanding)
        bottom_buttons_layout.addWidget(self.about_button)

        self.settings_button = QPushButton("Thiết lập Nâng cao")
        self.settings_button.clicked.connect(self.show_settings_dialog)
        self.settings_button.setMinimumHeight(45)
        self.settings_button.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Expanding)
        bottom_buttons_layout.addWidget(self.settings_button)
        
        main_layout.addLayout(bottom_buttons_layout)

        if not os.path.exists(ICON_FILE):
            try:
                if _has_pillow:
                    img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
                    img.save(ICON_FILE)
                    logging.info(f"Created a dummy {ICON_FILE}. Please replace it with a proper icon.")
                else:
                    logging.warning(f"'{ICON_FILE}' not found. No Pillow to create dummy icon. Icon might not display.")
            except Exception as e:
                logging.error(f"Failed to create dummy {ICON_FILE}: {e}")

    def set_tray_icon_reference(self, tray_icon):
        self.tray_icon_ref = tray_icon

    def load_initial_state(self):
        self.set_checkbox_state_safely(self.auto_lock_checkbox, self.settings.get_setting("auto_lock_enabled") == "True")
        self.set_checkbox_state_safely(self.run_on_startup_checkbox, self.settings.check_run_on_startup())
        
        if _has_scapy:
            if not is_admin():
                self.arp_stealth_checkbox.setEnabled(False)
                self.arp_stealth_checkbox.setText("Bảo vệ ARP chủ động (Yêu cầu Npcap & Quyền Admin)")
                self.arp_stealth_checkbox.setStyleSheet("color: #888888;")
                self.settings.set_setting("arp_stealth_enabled", "False") 
            else:
                self.set_checkbox_state_safely(self.arp_stealth_checkbox, self.settings.get_setting("arp_stealth_enabled") == "True")
        
        last_gateway = self.settings.get_setting("last_locked_gateway")
        last_mac = self.settings.get_setting("last_locked_mac")
        if last_gateway and last_mac:
            self.status_label.setText("Trạng thái trước: Đã khóa")
            self.status_label.setStyleSheet("color: #FFA500;")
            self.gateway_label.setText(f"Gateway: {last_gateway}")
            self.mac_label.setText(f"MAC: {last_mac}")
        else:
            self.status_label.setText("Trạng thái trước: Chưa có thông tin")
            self.status_label.setStyleSheet("color: #AAAAAA;")

    def connect_signals(self):
        self.arp_manager.status_signal.connect(self.update_status_display)
        self.arp_manager.log_signal.connect(self.append_log)
        self.arp_manager.setting_changed_signal.connect(self.sync_checkbox_state)

    def set_checkbox_state_safely(self, checkbox_or_action, state):
        if checkbox_or_action is None: return 
        checkbox_or_action.blockSignals(True)
        checkbox_or_action.setChecked(state)
        checkbox_or_action.blockSignals(False)

    def sync_checkbox_state(self, setting_key: str, state: bool):
        if setting_key == "auto_lock_enabled":
            self.set_checkbox_state_safely(self.auto_lock_checkbox, state)
            if self.tray_icon_ref and self.tray_icon_ref.auto_lock_action:
                self.set_checkbox_state_safely(self.tray_icon_ref.auto_lock_action, state)
        elif setting_key == "run_on_startup":
            self.set_checkbox_state_safely(self.run_on_startup_checkbox, state)
            if self.tray_icon_ref and self.tray_icon_ref.run_on_startup_action:
                self.set_checkbox_state_safely(self.tray_icon_ref.run_on_startup_action, state)
        elif setting_key == "arp_stealth_enabled":
            if isinstance(self.arp_stealth_checkbox, QCheckBox):
                self.set_checkbox_state_safely(self.arp_stealth_checkbox, state)
            if self.tray_icon_ref and self.tray_icon_ref.arp_stealth_action:
                self.set_action_state_safely(self.tray_icon_ref.arp_stealth_action, state) # Use action safe set here

    def update_status_display(self, status: str, gateway_ip: str, gateway_mac: str):
        self.status_label.setText(f"Trạng thái: {status}")
        if status == "Đã khóa":
            self.status_label.setStyleSheet("color: #32CD32;")
        elif status.startswith("Lỗi"):
            self.status_label.setStyleSheet("color: #FF6347;")
        elif status == "Tắt" or status == "Chờ mạng":
            self.status_label.setStyleSheet("color: #AAAAAA;")
        else:
            self.status_label.setStyleSheet("color: #87CEEB;")

        self.gateway_label.setText(f"Gateway: {gateway_ip}")
        self.mac_label.setText(f"MAC: {gateway_mac}")

    def append_log(self, message: str):
        cursor = self.log_text_edit.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        char_format = QTextCharFormat()
        if "[*]" in message:
            char_format.setForeground(QColor("#00FF00"))
        elif "[!]" in message:
            char_format.setForeground(QColor("#FF4500"))
        else:
            char_format.setForeground(QColor("#FFFFFF"))
            
        cursor.insertText(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n", char_format)
        self.log_text_edit.setTextCursor(cursor)
        self.log_text_edit.ensureCursorVisible()

    def on_auto_lock_checkbox_changed(self, state):
        enabled = state == Qt.Checked
        self.settings.set_setting("auto_lock_enabled", str(enabled))
        self.sync_checkbox_state("auto_lock_enabled", enabled)
        QTimer.singleShot(100, self.arp_manager.periodic_check)

    def on_run_on_startup_checkbox_changed(self, state):
        enabled = state == Qt.Checked
        if self.settings.set_run_on_startup(enabled):
            self.append_log(f"Chạy cùng Windows đã được {'BẬT' if enabled else 'TẮT'}.")
            self.sync_checkbox_state("run_on_startup", enabled)
        else:
            self.set_checkbox_state_safely(self.run_on_startup_checkbox, not enabled)
            QMessageBox.warning(self, "Lỗi Thiết lập", "Không thể thay đổi cài đặt 'Chạy cùng Windows'. Vui lòng chạy lại với quyền Admin.")

    def on_arp_stealth_checkbox_changed(self, state):
        enabled = state == Qt.Checked
        if not is_admin():
            QMessageBox.critical(self, "Lỗi Quyền Admin", "Vui lòng chạy chương trình với quyền quản trị để bật/tắt Bảo vệ ARP chủ động.")
            self.set_checkbox_state_safely(self.arp_stealth_checkbox, not enabled)
            return
        
        self.settings.set_setting("arp_stealth_enabled", str(enabled))
        self.sync_checkbox_state("arp_stealth_enabled", enabled)
        self.append_log(f"Bảo vệ ARP chủ động đã được {'BẬT' if enabled else 'TẮT'}.")
        QTimer.singleShot(100, self.arp_manager.periodic_check)

    def force_lock_arp(self):
        reply = QMessageBox.question(self, 'Xác nhận',
                                     "Bạn có chắc chắn muốn khóa ARP ngay lập tức cho Gateway hiện tại không?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            if not is_admin():
                QMessageBox.critical(self, "Lỗi Quyền Admin", "Vui lòng chạy chương trình với quyền quản trị để thực hiện thao tác này.")
                return

            self.append_log("Đang gửi yêu cầu khóa ARP thủ công đến tiến trình nền...")
            self.arp_manager.force_lock_signal.emit()

    def reset_arp_to_default_manual(self):
        # We need the currently locked gateway IP from settings
        gateway_to_reset = self.settings.get_setting("last_locked_gateway", "")

        if not gateway_to_reset:
            QMessageBox.warning(self, "Không có Gateway", "Không có Gateway nào được khóa trước đó để reset ARP.")
            return

        reply = QMessageBox.question(self, 'Xác nhận',
                                     f"Bạn có chắc chắn muốn reset ARP entry cho Gateway {gateway_to_reset} về mặc định không?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            if not is_admin():
                QMessageBox.critical(self, "Lỗi Quyền Admin", "Vui lòng chạy chương trình với quyền quản trị để thực hiện thao tác này.")
                return

            self.append_log(f"Yêu cầu reset ARP cho {gateway_to_reset} về mặc định...")
            if reset_arp_to_default(gateway_to_reset):
                self.append_log(f"[*] Đã reset ARP cho {gateway_to_reset} về mặc định.")
                # Update status display to reflect a reset state
                self.update_status_display("Đã reset", gateway_to_reset, "N/A")
                
                # Clear all persisted network info as it's no longer locked
                self.settings.set_setting("last_locked_gateway", "")
                self.settings.set_setting("last_locked_mac", "")
                self.settings.set_setting("last_network_id", "")
                self.settings.set_setting("last_host_ip", "")
                self.settings.set_setting("last_adapter_name", "")

                # Reset ARPManager's internal state to trigger re-lock logic
                self.arp_manager._is_locked_successfully = False 
                self.arp_manager.net_info = { 
                    "gateway_ip": None, "host_ip": None, "host_mac": None, 
                    "adapter_name": None, "adapter_guid": None, "ifindex": None, 
                    "network_id": None, "gateway_mac": None
                }
                self.arp_manager.scapy_iface_name = None
                
                if self.arp_manager.arp_stealth_monitor:
                    self.arp_manager.arp_stealth_monitor.stop()
                    self.arp_manager.arp_stealth_monitor = None
                    self.append_log("Đã dừng ARP Stealth sau khi reset ARP thủ công.")

                QTimer.singleShot(100, self.arp_manager.periodic_check) # Trigger re-check
            else:
                self.append_log(f"[!] Lỗi khi reset ARP cho {gateway_to_reset}.")
                QMessageBox.critical(self, "Lỗi", f"Không thể reset ARP entry cho {gateway_to_reset}.")

    def show_about_dialog(self):
        about_text = (
            f"<b>{APP_NAME} v{APP_VERSION}</b><br><br>"
            "Phần mềm bảo vệ máy tính của bạn khỏi các cuộc tấn công ARP spoofing (giả mạo ARP) trong mạng cục bộ.<br><br>"
            "<b>Tính năng chính:</b><br>"
            "<ul>"
            "<li>Tự động khóa ARP tĩnh cho Gateway mỗi khi thay đổi mạng.</li>"
            "<li>Chủ động bảo vệ (ARP Stealth) bằng cách chỉ trả lời yêu cầu ARP từ Router.</li>"
            "<li>Chạy nền, khởi động cùng Windows, và quản lý qua khay hệ thống.</li>"
            "<li>Các tùy chọn 'Chế độ tàng hình' nâng cao giúp giảm khả năng bị phát hiện trên mạng.</li>"
            "</ul><br>"
            "<b>Nhà phát triển:</b><br>"
            "Nam Trần<br>"
            "Email: <a href='mailto:namtran5905@gmail.com'>namtran5905@gmail.com</a><br>"
            "<br>"
            "<i>Lưu ý: Yêu cầu quyền quản trị (Administrator) để hoạt động. "
            "Tính năng bảo vệ ARP chủ động cần Scapy và Npcap đã cài đặt.</i>"
        )
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(f"Về {APP_NAME}")
        msg_box.setTextFormat(Qt.RichText)
        msg_box.setText(about_text)
        msg_box.setInformativeText("Bấm OK để đóng.")
        msg_box.setIcon(QMessageBox.Information)
        msg_box.exec_()

    def show_settings_dialog(self):
        settings_dialog = SettingsDialog(self.settings, self.arp_manager, self)
        settings_dialog.exec_()

    def closeEvent(self, event):
        if self.isVisible():
            reply = QMessageBox.question(self, 'Thoát ' + APP_NAME,
                                         "Bạn có muốn thoát hoàn toàn ARP Guardian không?\n"
                                         "Chọn 'No' để thu nhỏ ra khay hệ thống.",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                event.accept()
                QApplication.quit()
            else:
                event.ignore()
                self.hide()
        else:
            event.ignore()


# --- System Tray Icon ---
class SystemTrayIcon(QSystemTrayIcon):
    def __init__(self, main_window: MainWindow, settings: SettingsManager, parent=None):
        super().__init__(QIcon(ICON_FILE), parent)
        self.main_window = main_window
        self.settings = settings
        self.setToolTip(APP_NAME)
        self.init_menu()
        self.activated.connect(self.on_tray_activated)

    def init_menu(self):
        menu = QMenu()

        open_action = QAction("Mở " + APP_NAME, self)
        open_action.triggered.connect(self.main_window.showNormal)
        menu.addAction(open_action)

        menu.addSeparator()

        self.auto_lock_action = QAction("Tự động khóa ARP", self, checkable=True)
        self.auto_lock_action.setChecked(self.settings.get_setting("auto_lock_enabled") == "True")
        self.auto_lock_action.triggered.connect(self.on_auto_lock_action_changed)
        menu.addAction(self.auto_lock_action)
        
        if _has_scapy:
            self.arp_stealth_action = QAction("Bảo vệ ARP chủ động", self, checkable=True)
            self.arp_stealth_action.setChecked(self.settings.get_setting("arp_stealth_enabled") == "True")
            self.arp_stealth_action.triggered.connect(self.on_arp_stealth_action_changed)
            if not is_admin():
                self.arp_stealth_action.setEnabled(False)
                self.arp_stealth_action.setText(self.arp_stealth_action.text() + " (Chỉ Admin)")
            menu.addAction(self.arp_stealth_action)
        else:
            disabled_stealth_action = QAction("Bảo vệ ARP chủ động (Không khả dụng - Thiếu Scapy/Npcap)", self)
            disabled_stealth_action.setEnabled(False)
            menu.addAction(disabled_stealth_action)

        self.run_on_startup_action = QAction("Chạy cùng Windows", self, checkable=True)
        self.run_on_startup_action.setChecked(self.settings.check_run_on_startup())
        self.run_on_startup_action.triggered.connect(self.on_run_on_startup_action_changed)
        menu.addAction(self.run_on_startup_action)

        menu.addSeparator()

        show_log_action = QAction("Xem Log", self)
        show_log_action.triggered.connect(self.show_log_file)
        menu.addAction(show_log_action)

        about_action = QAction("Về " + APP_NAME, self)
        about_action.triggered.connect(self.main_window.show_about_dialog)
        menu.addAction(about_action)

        settings_action = QAction("Thiết lập Nâng cao", self)
        settings_action.triggered.connect(self.main_window.show_settings_dialog)
        menu.addAction(settings_action)

        exit_action = QAction("Thoát", self)
        exit_action.triggered.connect(self.exit_app)
        menu.addAction(exit_action)

        self.setContextMenu(menu)

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.main_window.showNormal()

    def set_action_state_safely(self, action, state):
        action.blockSignals(True)
        action.setChecked(state)
        action.blockSignals(False)

    def on_auto_lock_action_changed(self):
        enabled = self.auto_lock_action.isChecked()
        self.main_window.on_auto_lock_checkbox_changed(Qt.Checked if enabled else Qt.Unchecked)

    def on_arp_stealth_action_changed(self):
        enabled = self.arp_stealth_action.isChecked()
        self.main_window.on_arp_stealth_checkbox_changed(Qt.Checked if enabled else Qt.Unchecked)

    def on_run_on_startup_action_changed(self):
        enabled = self.run_on_startup_action.isChecked()
        self.main_window.on_run_on_startup_checkbox_changed(Qt.Checked if enabled else Qt.Unchecked)

    def show_log_file(self):
        try:
            os.startfile(LOG_FILE)
        except Exception as e:
            QMessageBox.critical(self.main_window, "Lỗi", f"Không thể mở file log: {e}")
            self.main_window.append_log(f"[!] Lỗi khi mở file log: {e}")

    def exit_app(self):
        reply = QMessageBox.question(self.main_window, 'Thoát ' + APP_NAME,
                                     "Bạn có chắc chắn muốn thoát ARP Guardian không?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No:
            return 
        
        self.main_window.arp_manager.stop()
        QApplication.quit()

# --- Main Application Entry Point ---
def set_dark_theme(app: QApplication):
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
    palette.setColor(QPalette.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
    palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
    palette.setColor(QPalette.Text, QColor(255, 255, 255))
    palette.setColor(QPalette.Button, QColor(70, 70, 70))
    palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
    palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
    
    palette.setColor(QPalette.Active, QPalette.Midlight, QColor(90, 90, 90))
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor(128, 128, 128))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(128, 128, 128))
    
    app.setPalette(palette)
    font = QFont("Segoe UI", 9)
    app.setFont(font)


if __name__ == "__main__":
    try:
        if hasattr(sys, 'frozen'):
            pywin32_system32 = os.path.join(sys._MEIPASS, 'pywin32_system32')
            pywin32_dlls = os.path.join(sys._MEIPASS, 'pywin32_dlls')
            if os.path.exists(pywin32_system32):
                os.add_dll_directory(pywin32_system32)
            if os.path.exists(pywin32_dlls):
                os.add_dll_directory(pywin32_dlls)
    except Exception as e:
        print(f"Warning: Could not add pywin32 DLL directory: {e}", file=sys.stderr)

    if not is_admin():
        restart_as_admin()

    setup_logging()

    app = QApplication(sys.argv)
    set_dark_theme(app)
    app.setQuitOnLastWindowClosed(False)

    settings = SettingsManager()
    
    arp_manager = ARPManager(settings)
    arp_manager.start()

    main_window = MainWindow(arp_manager, settings)
    
    tray_icon = SystemTrayIcon(main_window, settings)
    main_window.set_tray_icon_reference(tray_icon) 
    tray_icon.show()

    if settings.get_setting("run_on_startup") == "True" and settings.check_run_on_startup():
        main_window.hide()
    else:
        main_window.show()

    sys.exit(app.exec_())