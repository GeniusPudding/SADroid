import os
import shutil
import json
import sys
import subprocess
from time import process_time 
import re
import random
from tqdm import tqdm
from smali_utils.core_SADroid_logger import walk_smali_dir

def patch_log_file(smali_base_dir):

    inject_dir = os.path.join(smali_base_dir,'SADroid')
    if not os.path.isdir(inject_dir):
        os.mkdir(inject_dir)
    # log_dir = os.path.join(inject_dir,'logs')
    # os.mkdir(log_dir)
    shutil.copyfile(os.path.join(os.path.dirname(__file__),'smali_utils','injections','logs','InlineLogs.smali'), os.path.join(inject_dir,'InlineLogs.smali'))
    return 

def methodlog_instrumentation(target_apk_path, redecompile, target_API_graph, add_dummy_evasion = False):
    print(f'testing_apk_path:{target_apk_path}')
    if not os.path.exists(target_apk_path):
        raise ValueError("APK does not exist.")
    
    # param: target apk path that want to apply instrumentation method 
    # return: repackaged apk path   
    dirname, basename = os.path.split(target_apk_path)
    apk_name = os.path.splitext(basename)[0]
    apktool_dir = os.path.join(dirname,apk_name)
    #1.apktool decompile
    if redecompile:
        try:
            print('apktool -rf d --only-main-classes '+os.path.join(target_apk_path)+' -o '+apktool_dir)
            f = os.popen('apktool.bat -rf d --only-main-classes '+'\"'+target_apk_path+'\"'+' -o '+'\"'+apktool_dir+'\"').read()#.read() for blocking
            print(f)
        except :
            print('apktool decompile failed, check the apktool')
            raise RuntimeError('Failed to decompile this apk, check the apktool') 
    print('bytecode instrumentation')
 
    #print(f'main_activity:{main_activity}')
    smali_dirs = [subdir for subdir in os.listdir(apktool_dir) if subdir.startswith('smali')]
    next_smali_dir = os.path.join(apktool_dir,'smali_classes2' if len(smali_dirs) == 1 else 'smali_classes' + str(len(smali_dirs)+1))
    os.mkdir(next_smali_dir)
    for subdir in smali_dirs:
        #if subdir.startswith('smali'):
        #print(f'subdir:{subdir}')
        
        smali_base_dir = os.path.join(apktool_dir,subdir)
        #gen_invoke_set_json(smali_base_dir)
        s = walk_smali_dir(smali_base_dir, next_smali_dir, target_API_graph, apk_name)#, main_activity)
        #print(f's:{s}')
        #walk_target_dir(os.path.join(apktool_dir,subdir), graph)
    patch_log_file(os.path.join(apktool_dir,'smali'))

    if add_dummy_evasion:
        input('add_dummy_evasion')
        evasion_instrumentation(target_apk_path,False, 'methodStartLog()V')
    # except:   
    #     print('test Failed to do instrumentation')
    #     raise RuntimeError('Failed to do instrumentation')
    print('test repackage')
    #3.apk repackage
    try:
        #on win10
        f = os.popen('apktool.bat b '+'\"'+apktool_dir+'\"').read()#.read() for blocking
        print(f'apktool build:{f}')
        # r = subprocess.run(['apktool', 'b', apktool_dir], capture_output=True)
        # s = r.stdout.decode("utf-8").strip()
        build_path = os.path.join(apktool_dir,'dist', apk_name+'.apk')
        build_path2 = os.path.join(apktool_dir,'dist', apk_name+'_2.apk')
        repackaged_apk_path = os.path.join(dirname,'repacked_'+apk_name+'.apk')
        command = ["zipalign", "-f", "-v", "4", build_path, build_path2]
        try:
            subprocess.check_call(command)
            print(f"Zipalign successful, output saved to {build_path}")
        except subprocess.CalledProcessError as e:
            print(f"Zipalign failed with error: {e}")
        os.system('apksigner sign --ks '+ os.path.join(os.getcwd(), 'apkmaster','res','1.keystore')  + ' --ks-pass pass:s35gj6 --out ' + repackaged_apk_path + ' ' + build_path2)
        
        #shutil.copy2(build_path , repackaged_apk_path)

        # input(f'apktool build:{s}')
        # repackage = os.path.join(os.getcwd(), 'apkmaster','batches','repackage.bat')
        # cmd = [repackage,dirname,apk_name]# apktool_dir.rstrip('\\/')]
        # print(f'cmd:{cmd}')
        # r = subprocess.check_output(cmd).decode()
        # packagename = r.split('\r\n')[-2]
        # print(f'check output:{r}')
        # #TODO: on Unix
    except:
        raise RuntimeError('Failed to repackage')

    print(f'methodlog_instrumentation:{repackaged_apk_path}')
    return  repackaged_apk_path

if __name__ == "__main__":
    with open('jsons/target_API_graph_all.json', 'r') as f:
        target_API_graph = json.load(f)
    data_path = sys.argv[1]
    if data_path[-4:] == '.apk':
        repackaged_apk_path = methodlog_instrumentation(data_path, True, target_API_graph)
        print(f'Instrumentation of {data_path} finished.')
        exit(0)
    dd = os.listdir(data_path)
    dataset = [a for a in dd if a[-4:] == '.apk' and not a.startswith('repacked_')]  


    failed_repacked = []
    mean = 0
    for a in tqdm(dataset):
        t1_start = process_time()  
        try:
            #input('wait')
            repackaged_apk_path = methodlog_instrumentation(os.path.join(data_path,a), True, target_API_graph)
            
        except Exception as e:
            print(f'Analyzing {a} failed, error:{e}')
            failed_repacked.append(a)
        t1_stop = process_time() 
        t = t1_stop - t1_start
        print(f'Time for {a}: {t}')  
        mean += t
    if dataset != []: mean /= len(dataset)
    print(f'平均執行時間:{mean}')
    input(f'failed_repacked:{failed_repacked} ')