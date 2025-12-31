import importlib
import os
import platform
from datetime import datetime

# ---------------------- Configuration ----------------------
def load_modules():
    modules = {}
    modules_dir = "modules"
    idx = 1
    for mod in os.listdir(modules_dir):
        path = os.path.join(modules_dir, mod)
        if os.path.isdir(path) and os.path.exists(os.path.join(path, f"{mod}.py")):
            modules[str(idx)] = mod
            modules[mod] = mod
            idx += 1
    return modules

MODULES = load_modules()

SAVE_FOLDER = os.path.join(os.path.expanduser("~"), "VulEasy")
history = []

# ---------------------- Run Modules ---------------------- 
def run_module(module_name):
    try:
        module = importlib.import_module(f"modules.{module_name}")

        if hasattr(module, "run"):
            result = module.run()
            history.append(module_name)

            if result:
                save_scan_to_txt(module_name, result)
        else:
            print("[ERROR] Module has no run() function")

    except Exception as e:
        print(f"[ERROR] Failed to run module: {e}")

# ---------------------- Utility Functions ----------------------
def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")

def save_scan_to_txt(module_name, content):
    if not os.path.exists(SAVE_FOLDER):
        os.makedirs(SAVE_FOLDER)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{module_name}_{timestamp}.txt"
    filepath = os.path.join(SAVE_FOLDER, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[INFO] Results saved to {filepath}")

def show_help():
    print("""
[ VulEasy Help ]
Global Commands:
  clear          - Clears the screen
  exit / quit    - Exit the program
  history        - Shows scan history
  clearhistory   - Clears scan history
  list           - Lists available modules
  help           - Shows this help message

[ Modules ] 
  sqli           - Run SQLi Module
  xss            - Run XSS Module
  fingerprint    - Run Fingerprint Module

Usage:
  1. Type a module number or name to select it.
  2. The module will handle the scan process (URL, GET/POST, payloads, etc.).
""")

def show_history():
    if history:
        print("\n[SCAN HISTORY]")
        for idx, entry in enumerate(history, start=1):
            print(f"{idx}. {entry}")
    else:
        print("[INFO] No history available.")

def clear_history():
    history.clear()
    print("[INFO] History cleared.")

def list_modules():
    print("\n[AVAILABLE MODULES]")
    for key, mod in MODULES.items():
        if key.isdigit():
            print(f"{key}. {mod.upper()}")

# ---------------------- Main ----------------------
def main():
    print(r"""__     ___   _ _     _____    _    ______   __
\ \   / / | | | |   | ____|  / \  / ___\ \ / /
 \ \ / /| | | | |   |  _|   / _ \ \___ \\ V / 
  \ V / | |_| | |___| |___ / ___ \ ___) || |  
   \_/   \___/|_____|_____/_/   \_\____/ |_|  

     Type 'help' for assistance""")

    COMMANDS = {
        "exit": lambda: exit(0),
        "quit": lambda: exit(0),
        "clear": clear_screen,
        "help": show_help,
        "history": show_history,
        "clearhistory": clear_history,
        "list": list_modules,
    }

    while True:
        user_input = input("\nVulEasy> ").strip().lower()

        if not user_input:
            continue

        if user_input in COMMANDS:
            COMMANDS[user_input]()
            continue

        if user_input in MODULES:
            module_name = MODULES[user_input]
            run_module(module_name)
            continue

        print("[ERROR] Unknown command or module. Type 'help' to see available commands.")

if __name__ == "__main__":
    main()