import subprocess
import time


def is_emulator_alive(emulator_name):
    # Run adb command to check the state of the emulator
    result = subprocess.run(['adb', 'emu', 'status', emulator_name], capture_output=True, text=True)

    # Check if the output contains "booted" which indicates that the emulator is alive
    return "booted" in result.stdout.lower()


def start_emulator(emulator_name):
    # Run adb command to start the emulator in detached mode
    subprocess.Popen(['emulator', '@' + emulator_name, '-no-snapshot-save', '-no-boot-anim', '-no-audio'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


if __name__ == "__main__":
    predefined = ['Pixel_6a_API_32']
    check_interval = 600  # 10 minutes in seconds

    while True:
        for dev in predefined:
            device_status = is_emulator_alive(dev)
            print(device_status)

            if not device_status:
                start_emulator(dev)
        time.sleep(check_interval)