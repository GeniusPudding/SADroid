import os
from tqdm import tqdm
import hashlib

hash_sign = lambda sign: hashlib.sha256(sign.encode('utf-8')).hexdigest()[:16]  # use 16 chars to identify

def scan_logcat_folders(logcat_dir, target_hash):
    real_device_apps = set()
    emulator_apps = set()

    for app_name in tqdm(os.listdir(logcat_dir)):
        app_hash = hash_sign(app_name)
        app_dir = os.path.join(logcat_dir, app_name)
        if os.path.isdir(app_dir):
            real_device_found = False
            emulator_found = False
            for log_file in os.listdir(app_dir):
                if 'logcat_output' in log_file:
                    log_file_path = os.path.join(app_dir, log_file)
                    with open(log_file_path, 'r') as f:
                        for line in f:
                            if target_hash in line and app_hash in line:
                                if 'emulator' in log_file and not emulator_found:
                                    emulator_apps.add(app_name)
                                    emulator_found = True
                                elif 'emulator' not in log_file and not real_device_found:
                                    real_device_apps.add(app_name)
                                    real_device_found = True
                                if real_device_found and emulator_found:
                                    break
                    if real_device_found and emulator_found:
                        break

    print("Real Device Apps:")
    for app in real_device_apps:
        print(app)

    print("\nEmulator Apps:")
    for app in emulator_apps:
        print(app)
    print(f"Real Device: {len(real_device_apps)} apps contain the target hash.")

    print(f"Emulator: {len(emulator_apps)} apps contain the target hash.")

# 指定 logcat 資料夾路徑和目標 hash 值
logcat_dir = 'logcat'
target_hash = '0dd02a084fbcf82f'

scan_logcat_folders(logcat_dir, target_hash)