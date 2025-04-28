import os
import time
import psutil
import tkinter as tk
import threading
import re
import shutil
import smtplib
import requests
from email.mime.text import MIMEText
from dotenv import load_dotenv
from tkinter import ttk, messagebox, scrolledtext

# Load environment variables
load_dotenv()

MONITOR_PATH = os.path.expanduser("~")

# Email configuration
EMAIL_ENABLED = True  # Set to False to disable emails
SENDER_EMAIL = "k214602@nu.edu.pk"
RECIPIENT_EMAILS = ["ammarq18@hotmail.com"]
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Pushover configuration
PUSHOVER_ENABLED = True  # Set to False to disable Pushover notifications
PUSHOVER_USER_KEY = os.getenv("PUSHOVER_USER_KEY")
PUSHOVER_API_TOKEN = os.getenv("PUSHOVER_API_TOKEN")

class AdvancedDetectorGUI:
    def _init_(self, master):
        self.master = master
        master.title("Advanced Security Monitor")
        
        self.create_widgets()
        self.running = True
        self.last_alert_time = 0
        self.alert_cooldown = 10  # 10 seconds between alerts
        
        # Email setup validation
        if EMAIL_ENABLED and not SMTP_PASSWORD:
            self.log_message("Email password not found in .env file. Email alerts disabled.")
        
        # Pushover setup validation
        if PUSHOVER_ENABLED and (not PUSHOVER_USER_KEY or not PUSHOVER_API_TOKEN):
            self.log_message("Pushover keys not found. Pushover alerts disabled.")
        
        # Initialize monitoring
        self.baseline_sizes = self.get_directory_sizes()
        self.dir_growth = {path: 0 for path in self.baseline_sizes}
        self.monitor_thread = threading.Thread(target=self.monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def create_widgets(self):
        self.log_area = scrolledtext.ScrolledText(self.master, wrap=tk.WORD)
        self.log_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        self.status_frame = ttk.Frame(self.master)
        self.status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.process_label = ttk.Label(self.status_frame, text="Running Keyloggers: 0")
        self.process_label.pack(side=tk.LEFT)
        
        self.log_label = ttk.Label(self.status_frame, text="Hidden Logs: 0")
        self.log_label.pack(side=tk.LEFT, padx=20)
        
        self.dir_label = ttk.Label(self.status_frame, text="Suspicious Dirs: 0")
        self.dir_label.pack(side=tk.RIGHT)
    
    def log_message(self, message):
        self.log_area.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
        self.log_area.see(tk.END)
    
    def detect_running_keyloggers(self):
        keylogger_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                info = proc.info
                if self.is_keylogger_process(info):
                    keylogger_processes.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return keylogger_processes
    
    def is_keylogger_process(self, process_info):
        # Exclude known safe processes
        safe_processes = {"gnome-keyring-daemon", "systemd", "init", "gpg-agent"}
        proc_name = (process_info['name'] or "").lower()
        if proc_name in safe_processes:
            return False

        indicators = [
            r"keylogger", r"keystroke", r"key.*capture",
            r"key.*stroke", r"key.*press", r"key.*monitor"
        ]
        
        target_str = " ".join([
            process_info['name'] or "",
            " ".join(process_info['cmdline'] or []),
            process_info['exe'] or ""
        ]).lower()
        
        return any(re.search(pattern, target_str) for pattern in indicators)
    
    def detect_hidden_logs(self):
        hidden_logs = []
        for root, dirs, files in os.walk(MONITOR_PATH):
            for file in files:
                if file.startswith('.') and file.endswith(('.log', '.tmp')):
                    file_path = os.path.join(root, file)
                    if self.is_keylogger_log(file_path):
                        hidden_logs.append(file_path)
        return hidden_logs
    
    def is_keylogger_log(self, file_path):
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read(2048)
                patterns = [
                    r"Key Pressed:.*",
                    r"Key (Press|Release|Stroke).*,",
                    r"\[(Shift|Ctrl|Alt|Enter|Backspace)\]",
                    r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
                ]
                return any(re.search(pattern, content) for pattern in patterns)
        except Exception:
            return False
    
    def is_safe_directory(self, dir_path):
        safe_keywords = ['mozilla', 'font', 'trash', 'cache', 'config']
        return any(kw in dir_path.lower() for kw in safe_keywords)
    
    def detect_suspicious_dirs(self):
        current_sizes = self.get_directory_sizes()
        suspicious = []
        for path, current_size in current_sizes.items():
            prev_size = self.baseline_sizes.get(path, 0)
            diff = current_size - prev_size
            if diff > 0:
                self.dir_growth[path] = self.dir_growth.get(path, 0) + diff
            if self.dir_growth.get(path, 0) > 1 * 1024 * 1024:  # 5MB
                suspicious.append(path)
        self.baseline_sizes = current_sizes
        return suspicious
    
    def get_directory_sizes(self):
        sizes = {}
        for root, dirs, _ in os.walk(MONITOR_PATH):
            for d in dirs:
                if d.startswith('.') and not self.is_safe_directory(d):
                    dir_path = os.path.join(root, d)
                    sizes[dir_path] = self.calculate_dir_size(dir_path)
        return sizes
    
    def calculate_dir_size(self, directory):
        total_size = 0
        for dirpath, _, files in os.walk(directory):
            for f in files:
                file_path = os.path.join(dirpath, f)
                if os.path.exists(file_path):
                    try:
                        total_size += os.path.getsize(file_path)
                    except Exception:
                        pass
        return total_size
    
    def send_email_alert(self, subject, message):
        if not EMAIL_ENABLED or not SMTP_PASSWORD:
            return
        if time.time() - self.last_alert_time < self.alert_cooldown:
            return
        try:
            msg = MIMEText(message)
            msg["Subject"] = f"Security Alert: {subject}"
            msg["From"] = SENDER_EMAIL
            msg["To"] = ", ".join(RECIPIENT_EMAILS)
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SENDER_EMAIL, SMTP_PASSWORD)
                server.sendmail(SENDER_EMAIL, RECIPIENT_EMAILS, msg.as_string())
            self.last_alert_time = time.time()
            self.log_message("Email alert sent successfully")
        except Exception as e:
            self.log_message(f"Email failed: {str(e)}")
        # Now also send Pushover
        if PUSHOVER_ENABLED and PUSHOVER_USER_KEY and PUSHOVER_API_TOKEN:
            self.send_pushover_notification(subject, message)
    
    def send_pushover_notification(self, title, message):
        try:
            payload = {
                'token': PUSHOVER_API_TOKEN,
                'user': PUSHOVER_USER_KEY,
                'title': f"Security Alert: {title}",
                'message': message
            }
            resp = requests.post("https://api.pushover.net/1/messages.json", data=payload)
            if resp.status_code == 200:
                self.log_message("Pushover alert sent successfully")
            else:
                e_msg = resp.json().get('errors') if resp.headers.get('Content-Type','').startswith('application/json') else resp.text
                self.log_message(f"Pushover failed: {e_msg}")
        except Exception as e:
            self.log_message(f"Pushover error: {str(e)}")

    def monitor(self):
        while self.running:
            # Detect running keyloggers
            keyloggers = self.detect_running_keyloggers()
            self.master.after(0, self.process_label.config, {"text": f"Running Keyloggers: {len(keyloggers)}"})
            for proc in keyloggers:
                alert_msg = f"Keylogger process: {proc.info['name']} (PID: {proc.info['pid']})"
                self.log_message(alert_msg)
                self.send_email_alert("Keylogger Detected", alert_msg)
                self.show_action_dialog(
                    "Keylogger Process Detected",
                    f"Keylogger process detected:\n{proc.info['name']}\nPID: {proc.info['pid']}",
                    lambda p=proc: self.stop_keylogger_process(p)
                )
            # Detect hidden logs
            hidden_logs = self.detect_hidden_logs()
            self.master.after(0, self.log_label.config, {"text": f"Hidden Logs: {len(hidden_logs)}"})
            for log_file in hidden_logs:
                alert_msg = f"Hidden log: {log_file}"
                self.log_message(alert_msg)
                self.send_email_alert("Suspicious Log File", alert_msg)
                self.show_action_dialog(
                    "Hidden Log File Detected",
                    f"Hidden keylogger log detected:\n{log_file}",
                    lambda lf=log_file: self.delete_log_file(lf)
                )
            # Detect suspicious directories
            suspicious_dirs = self.detect_suspicious_dirs()
            filtered_dirs = [d for d in suspicious_dirs if not self.is_safe_directory(d)]
            self.master.after(0, self.dir_label.config, {"text": f"Suspicious Dirs: {len(filtered_dirs)}"})
            for dir_path in filtered_dirs:
                alert_msg = f"Directory growth: {dir_path}"
                self.log_message(alert_msg)
                self.send_email_alert("Suspicious Directory", alert_msg)
                self.show_action_dialog(
                    "Suspicious Directory Growth",
                    f"Directory growing abnormally:\n{dir_path}",
                    lambda dp=dir_path: self.delete_directory(dp)
                )
            time.sleep(10)

    def stop_keylogger_process(self, proc):
        try:
            proc.terminate()
            self.log_message(f"Stopped process: {proc.info['name']} (PID: {proc.info['pid']})")
        except Exception as e:
            self.log_message(f"Process stop failed: {str(e)}")

    def delete_log_file(self, file_path):
        try:
            os.remove(file_path)
            self.log_message(f"Deleted log: {file_path}")
        except Exception as e:
            self.log_message(f"Delete failed: {str(e)}")

    def delete_directory(self, dir_path):
        try:
            shutil.rmtree(dir_path)
            self.log_message(f"Deleted directory: {dir_path}")
        except Exception as e:
            self.log_message(f"Directory delete failed: {str(e)}")

    def show_action_dialog(self, title, message, action):
        response = messagebox.askyesno(title, f"{message}\n\nTake action?")
        if response:
            try:
                action()
                self.log_message("Action successful")
            except Exception as e:
                self.log_message(f"Action failed: {str(e)}")

    def on_closing(self):
        self.running = False
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    gui = AdvancedDetectorGUI(root)
    root.protocol("WM_DELETE_WINDOW", gui.on_closing)
    root.mainloop()