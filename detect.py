import os
import time
import psutil
import tkinter as tk
import threading
import re
import shutil
import smtplib
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
                    r"Key (Press|Release|Stroke).*",
                    r"\[(Shift|Ctrl|Alt|Enter|Backspace)\]",
                    r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
                ]
                return any(re.search(pattern, content) for pattern in patterns)
        except Exception:
            return False
        

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


if __name__ == "__main__":
    root = tk.Tk()
    gui = AdvancedDetectorGUI(root)
    root.protocol("WM_DELETE_WINDOW", gui.on_closing)
    root.mainloop()
