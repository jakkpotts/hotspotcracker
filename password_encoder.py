import base64
import hashlib
import random
import time

def replace_char_at(s, index, char):
    return s[:index] + char + s[index+1:]

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
    # For simplicity, use mix_all
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
        idx1 = ((parse16 >> (i * 8)) & 0xff) % len(splic_pwd)
        idx2 = i % len(splic_pwd)
        splic_pwd = replace_char_at(splic_pwd, idx1, splic_pwd[idx2])
        splic_pwd = replace_char_at(splic_pwd, idx2, splic_pwd[idx1])

    random1 = ''.join([f"{x:02x}" for x in num255])
    time_diff = int(time.time()) - timestamp_start
    time_stamp = int(timestamp, 16) + time_diff
    message = f"{random1}x{time_stamp:x}:{splic_pwd}"
    base64_str = base64.b64encode(message.encode()).decode()

    for i in range(4):
        idx1 = ((parse16 >> (i * 8)) & 0xff) % len(base64_str)
        idx2 = i % len(base64_str)
        base64_str = replace_char_at(base64_str, idx1, base64_str[idx2])
        base64_str = replace_char_at(base64_str, idx2, base64_str[idx1])

    return base64_str

if __name__ == '__main__':
    password_plain = 'admin123'
    secret = '2b661a2a'
    timestamp = '1ac'
    timestamp_start = 1743297969  # adjust to the correct start time

    md5_hash = hashlib.md5(password_plain.encode()).hexdigest()
    encoded = password_encode(md5_hash, secret, timestamp, timestamp_start)
    print("Encoded Password:", encoded)
