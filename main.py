import importlib
import os
import platform
from datetime import datetime

# ---------------------- Configuration ----------------------
MODULES = {
    "1": "sqli",
    "2": "xss",
    "3": "lfi",
    "4": "rce",
    # Add more modules here
}

SAVE_FOLDER = os.path.join(os.path.expanduser("~"), "VulEasy")
history = []

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
        print(f"{key}. {mod.upper()}")

# ---------------------- Main ----------------------
def main():
    print(r""" __      __    _ ______                
 \ \    / /   | |  ____|               
  \ \  / /   _| | |__   __ _ ___ _   _ 
   \ \/ / | | | |  __| / _` / __| | | |
    \  /| |_| | | |___| (_| \__ \ |_| |
     \/  \__,_|_|______\__,_|___/\__, |
                                  __/ |
                                 |___/ 
     Type 'help' for assistance""")

    while True:
        user_input = input("\nVulEasy> ").strip().lower()

        # --- Global commands ---
        if user_input in ("exit", "quit"):
            print("Goodbye!")
            break
        elif user_input == "clear":
            clear_screen()
            continue
        elif user_input == "help":
            show_help()
            continue
        elif user_input == "history":
            show_history()
            continue
        elif user_input == "clearhistory":
            clear_history()
            continue
        elif user_input == "list":
            list_modules()
            continue

        # --- Module selection ---
        if user_input in MODULES or user_input in MODULES.values():
            module_name = MODULES.get(user_input, user_input)

            try:
                scan_module = importlib.import_module(f"modules.{module_name}.scan_modes")
            except ModuleNotFoundError:
                print(f"[ERROR] Module '{module_name}' not found or incomplete.")
                continue

            # Try to get the run function
            try:
                run_func = getattr(scan_module, "run")  # Your module must have run()
            except AttributeError:
                print(f"[ERROR] Module '{module_name}' does not implement 'run()'.")
                continue

            print(f"[INFO] Launching {module_name.upper()} module...")
            try:
                # Run the module (it handles URL, GET/POST, payloads, etc.)
                run_func()
                history.append(f"{module_name.upper()} - executed")
            except Exception as e:
                print(f"[ERROR] Module execution failed: {e}")
        else:
            print("[ERROR] Unknown command or module. Type 'help' to see available commands.")

if __name__ == "__main__":
    main()
