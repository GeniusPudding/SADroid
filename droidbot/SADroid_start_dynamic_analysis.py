# helper file of droidbot
# it parses command arguments and send the options to droidbot
import argparse
from droidbot import input_manager
from droidbot import input_policy
from droidbot import env_manager
from droidbot import DroidBot
from droidbot.droidmaster import DroidMaster
from droidbot.utils import get_available_devices
import os
import sys
import subprocess
import random
from tqdm import tqdm
ignore_list = [
    'repacked_000B390A3721379376B43BD4481DB65C7EDB7C05514EB681B172CA959F85CD1C.apk'


]

def parse_args():
    """
    parse command line input
    generate options including host name, port number
    """
    parser = argparse.ArgumentParser(description="Start DroidBot to test an Android app.",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-d", action="store", dest="device_serial", required=False,
                        help="The serial number of target device (use `adb devices` to find)")
    parser.add_argument("-a", action="store", dest="apk_path", required=True,
                        help="The file path to target APK")
    parser.add_argument("-o", action="store", dest="output_dir", default=  "dynamic_analysis_output",
                        help="directory of output")
    # parser.add_argument("-env", action="store", dest="env_policy",
    #                     help="policy to set up environment. Supported policies:\n"
    #                          "none\tno environment will be set. App will run in default environment of device; \n"
    #                          "dummy\tadd some fake contacts, SMS log, call log; \n"
    #                          "static\tset environment based on static analysis result; \n"
    #                          "<file>\tget environment policy from a json file.\n")
    parser.add_argument("-policy", action="store", dest="input_policy", default=input_manager.DEFAULT_POLICY,
                        help='Policy to use for test input generation. '
                             'Default: %s.\nSupported policies:\n' % input_manager.DEFAULT_POLICY +
                             '  \"%s\" -- No event will be sent, user should interact manually with device; \n'
                             '  \"%s\" -- Use "adb shell monkey" to send events; \n'
                             '  \"%s\" -- Explore UI using a naive depth-first strategy;\n'
                             '  \"%s\" -- Explore UI using a greedy depth-first strategy;\n'
                             '  \"%s\" -- Explore UI using a naive breadth-first strategy;\n'
                             '  \"%s\" -- Explore UI using a greedy breadth-first strategy;\n'
                             %
                             (
                                 input_policy.POLICY_NONE,
                                 input_policy.POLICY_MONKEY,
                                 input_policy.POLICY_NAIVE_DFS,
                                 input_policy.POLICY_GREEDY_DFS,
                                 input_policy.POLICY_NAIVE_BFS,
                                 input_policy.POLICY_GREEDY_BFS,
                             ))

    # for distributed DroidBot
    parser.add_argument("-distributed", action="store", dest="distributed", choices=["master", "worker"],
                        help="Start DroidBot in distributed mode.")
    parser.add_argument("-master", action="store", dest="master",
                        help="DroidMaster's RPC address")
    parser.add_argument("-qemu_hda", action="store", dest="qemu_hda",
                        help="The QEMU's hda image")
    parser.add_argument("-qemu_no_graphic", action="store_true", dest="qemu_no_graphic",
                        help="Run QEMU with -nograpihc parameter")

    parser.add_argument("-script", action="store", dest="script_path",
                        help="Use a script to customize input for certain states.")
    parser.add_argument("-count", action="store", dest="count", default=input_manager.DEFAULT_EVENT_COUNT, type=int,
                        help="Number of events to generate in total. Default: %d" % input_manager.DEFAULT_EVENT_COUNT)
    parser.add_argument("-interval", action="store", dest="interval", default=input_manager.DEFAULT_EVENT_INTERVAL,
                        type=int,
                        help="Interval in seconds between each two events. Default: %d" % input_manager.DEFAULT_EVENT_INTERVAL)
    parser.add_argument("-timeout", action="store", dest="timeout", default=input_manager.DEFAULT_TIMEOUT, type=int,
                        help="Timeout in seconds, -1 means unlimited. Default: %d" % input_manager.DEFAULT_TIMEOUT)
    parser.add_argument("-cv", action="store_true", dest="cv_mode",
                        help="Use OpenCV (instead of UIAutomator) to identify UI components. CV mode requires opencv-python installed.")
    parser.add_argument("-debug", action="store_true", dest="debug_mode",
                        help="Run in debug mode (dump debug messages).")
    parser.add_argument("-random", action="store_true", dest="random_input",
                        help="Add randomness to input events.")
    parser.add_argument("-keep_app", action="store_true", dest="keep_app",
                        help="Keep the app on the device after testing.")
    parser.add_argument("-keep_env", action="store_true", dest="keep_env",
                        help="Keep the test environment (eg. minicap and accessibility service) after testing.")
    parser.add_argument("-use_method_profiling", action="store", dest="profiling_method",
                        help="Record method trace for each event. can be \"full\" or a sampling rate.")
    parser.add_argument("-grant_perm", action="store_true", dest="grant_perm",
                        help="Grant all permissions while installing. Useful for Android 6.0+.")
    parser.add_argument("-is_emulator", action="store_true", dest="is_emulator",
                        help="Declare the target device to be an emulator, which would be treated specially by DroidBot.")
    parser.add_argument("-accessibility_auto", action="store_true", dest="enable_accessibility_hard",
                        help="Enable the accessibility service automatically even though it might require device restart\n(can be useful for Android API level < 23).")
    parser.add_argument("-humanoid", action="store", dest="humanoid",
                        help="Connect to a Humanoid service (addr:port) for more human-like behaviors.")
    parser.add_argument("-ignore_ad", action="store_true", dest="ignore_ad",
                        help="Ignore Ad views by checking resource_id.")
    parser.add_argument("-replay_output", action="store", dest="replay_output",
                        help="The droidbot output directory being replayed.")
    options = parser.parse_args()
    # print options
    return options


def SADroid_droidbot_main(device_serial, opts, apk_path):
    """
    the main function
    it starts a droidbot according to the arguments given in cmd line
    """

    if not os.path.exists(apk_path):
        print("APK does not exist.")
        return
    if not opts.output_dir and opts.cv_mode:
        print("To run in CV mode, you need to specify an output dir (using -o option).")

    if opts.distributed:
        if opts.distributed == "master":
            start_mode = "master"
        else:
            start_mode = "worker"
    else:
        start_mode = "normal"

    try:
        if start_mode == "master":
            droidmaster = DroidMaster(
                app_path=apk_path,
                is_emulator=opts.is_emulator,
                output_dir=opts.output_dir,
                # env_policy=opts.env_policy,
                env_policy=env_manager.POLICY_NONE,
                policy_name=opts.input_policy,
                random_input=opts.random_input,
                script_path=opts.script_path,
                event_interval=opts.interval,
                timeout=opts.timeout,
                event_count=opts.count,
                cv_mode=opts.cv_mode,
                debug_mode=opts.debug_mode,
                keep_app=opts.keep_app,
                keep_env=opts.keep_env,
                profiling_method=opts.profiling_method,
                grant_perm=opts.grant_perm,
                enable_accessibility_hard=opts.enable_accessibility_hard,
                qemu_hda=opts.qemu_hda,
                qemu_no_graphic=opts.qemu_no_graphic,
                humanoid=opts.humanoid,
                ignore_ad=opts.ignore_ad,
                replay_output=opts.replay_output)
            droidmaster.start()
        else:
            droidbot = DroidBot(
                app_path=apk_path,
                device_serial=device_serial,
                is_emulator=opts.is_emulator,
                output_dir=opts.output_dir,
                # env_policy=opts.env_policy,
                env_policy=env_manager.POLICY_NONE,
                policy_name=opts.input_policy,
                random_input=opts.random_input,
                script_path=opts.script_path,
                event_interval=opts.interval,
                timeout=opts.timeout,
                event_count=opts.count,
                cv_mode=opts.cv_mode,
                debug_mode=opts.debug_mode,
                keep_app=opts.keep_app,
                keep_env=opts.keep_env,
                profiling_method=opts.profiling_method,
                grant_perm=opts.grant_perm,
                enable_accessibility_hard=opts.enable_accessibility_hard,
                master=opts.master,
                humanoid=opts.humanoid,
                ignore_ad=opts.ignore_ad,
                replay_output=opts.replay_output)
            
            print("start test")
            droidbot.start()
            print("test")
    except subprocess.CalledProcessError as e:
        print(f"Failed subprocess : {e}")
    except Exception as e:
        print("Main Error: %s" % e)
    return


if __name__ == "__main__":

    failed_apks = {}
    opts = parse_args()
    print("opts.apk_path: %s" % opts.apk_path)
    all_devices = get_available_devices()

    # outputs = os.listdir('./logcat')
    # uncompleted_dataset_list = []
    # for appname in outputs:
    #     for device_serial in all_devices:
    #         output_file = os.path.join('./logcat', appname, "[" + device_serial + "]_logcat_output.txt")
    #         if not os.path.exists(output_file):
    #             break
    #         # 如果output_file大小為0，代表沒有logcat輸出，也代表沒有成功測試
    #         if os.path.getsize(output_file) == 0:
    #             uncompleted_dataset_list += ["repacked_" + appname + ".apk"]
    #             break
    # input("uncompleted_dataset_list: %s" % uncompleted_dataset_list)    
               
    if(os.path.isdir(opts.apk_path)): # For SADroid dynamic analysis on apk dataset
        SADroid_dataset = [a for a in os.listdir(opts.apk_path) if a.endswith(".apk") and a.startswith("repacked_") and a not in ignore_list] # and a.replace(".apk", "").replace("repacked_", "") not in outputs]      
        # SADroid_dataset += uncompleted_dataset_list
        # filter out the apks that have been tested


        random.shuffle(SADroid_dataset)
        print("SADroid_dataset: %s" % SADroid_dataset)
        print("len(SADroid_dataset): %s" % len(SADroid_dataset))
        # SADroid_dataset = ["repacked_2DA4F4978C9C01E138DCCB9BD21D191B40F70FF796C1AB56B12A39E01B287434.apk"] + SADroid_dataset
        for apkname in tqdm(SADroid_dataset): # Run on all apks in dataset
            print("Current testing apk: %s" % apkname)
            # get the package name of the apk
            package_name = subprocess.check_output(["aapt", "dump", "badging", os.path.join(opts.apk_path, apkname)]).decode("utf-8").split("'")[1]

            all_devices = get_available_devices()
            print("Available devices: %s" % all_devices)
            apk_output_dir = os.path.join('./logcat', apkname.replace(".apk", "").replace("repacked_", ""))
            if not os.path.exists(apk_output_dir):
                os.makedirs(apk_output_dir)

            cycle_count = len([l for l in os.listdir(apk_output_dir) if '[emulator-5554]_logcat_output' in l])
            cycle_count = "_"+str(cycle_count) if cycle_count > 0 else ""
            # input(f"cycle_count: {cycle_count}")
            for device_serial in all_devices: # Run on all devices
                print("Current testing device: %s" % device_serial)

                #Init device
                try:
                    subprocess.run(['adb' , '-s', device_serial , 'shell', 'svc', 'wifi', 'enable'])#確保連網
                    os.system('adb -s ' + device_serial + ' logcat -G 16M')#增加logcat緩衝區大小
                except:
                    print('init exception')

                #Redirect this apk's output to subdir/files
                log_file_out = os.path.join(apk_output_dir, "["+device_serial+"]_output_log"+cycle_count+".txt")
                log_file_err = os.path.join(apk_output_dir, "["+device_serial+"]_error_log"+cycle_count+".txt")
                original_stdout = sys.stdout  # 保存原始 stdout
                original_stderr = sys.stderr  # 保存原始 stderr
                print(f'log_file_out: {log_file_out}')
                print(f'log_file_err: {log_file_err}')
                # 重定向標準輸出和標準錯誤到日誌文件
                sys.stdout = open(log_file_out, 'w')
                sys.stderr = open(log_file_err, 'w')

                #Apk's logcat output
                logcat_out_file = open(os.path.join(apk_output_dir, "["+device_serial+"]_logcat_output"+cycle_count+".txt"), 'w')
                logcat_err_file = open(os.path.join(apk_output_dir, "["+device_serial+"]_logcat_error"+cycle_count+".txt"), 'w')
                print(f'logcat_out_file: {logcat_out_file}')
                print(f'logcat_err_file: {logcat_err_file}')

                try:      
                    subprocess.Popen(["adb", "-s", device_serial, "logcat", "-c"])                  
                    SADroid_droidbot_main(device_serial, opts, os.path.join(opts.apk_path, apkname))
                   # adb uninstall the apk
                    # subprocess.Popen(["adb", "-s", device_serial, "uninstall", package_name])

                    subprocess.Popen(["adb", "-s", device_serial, "logcat", "SADroid:D", "*:S"], stdout= logcat_out_file,
                                stderr=subprocess.DEVNULL)
                    subprocess.Popen(["adb", "-s", device_serial, "logcat", "AndroidRuntime:E", "*:S"], stdout= logcat_err_file,
                                stderr=subprocess.DEVNULL)

                except Exception as e:
                    
                    failed_apks[apkname] = e
                    sys.stdout.close()
                    sys.stderr.close()
                    sys.stdout = original_stdout
                    sys.stderr = original_stderr
                    print(f"Failed apk: {apkname} on Exception: {e}")
                    continue
                sys.stdout.close()
                sys.stderr.close()
                sys.stdout = original_stdout
                sys.stderr = original_stderr
    elif opts.apk_path.endswith(".apk"): # Origin droidbot usage
        SADroid_droidbot_main(opts.device_serial, opts, opts.apk_path)

