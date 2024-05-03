import os 
import sys
import json
import sqlite3
import re
from droidbot.utils import get_available_devices
from smali_utils.core_SADroid_logger import hash_sign
from tqdm import tqdm
from collections import defaultdict
# with open(os.path.join('json', '.json'), 'r') as f:

# package_mapping = 

def log_to_blocklist(log_lines):
    blocklist = []
    cur_block = []
    for line in log_lines:
        if line == '\n':
            continue

        if '[Method START]' in line:
            if cur_block != []: #如果cur_block不是空的，則代表上一個block已經結束 通常應該要有個END
                blocklist.append(cur_block)
            cur_block = [line]
        elif '[TAG: ' in line:
            if cur_block != []:
                blocklist.append(cur_block)
            cur_block = [line]
        else:
            cur_block.append(line)
            if '[Method END]' in line:
                blocklist.append(cur_block)
                cur_block = []

    if cur_block != []:
        blocklist.append(cur_block)   
    # print(f'blocklist:{blocklist}')
    return blocklist

def find_evasion(app_logdir, conn):
    evasion = []
    
    for method_dir in os.listdir(app_logdir):
        method_sign = conn.execute('SELECT method_sign FROM method WHERE method_hash =?', (method_dir,)).fetchone()
        basepath = os.path.join(app_logdir, method_dir)
        real_device_log_file = os.path.join(basepath, 'real_device_log.txt')
        emu_device_log_file = os.path.join(basepath, 'emulator_device_log.txt')
        if not os.path.exists(real_device_log_file) or not os.path.exists(emu_device_log_file):
            continue
        with open(real_device_log_file, 'r') as f:
            real_log_lines = f.readlines() 
        with open(emu_device_log_file, 'r') as f:
            emu_log_lines = f.readlines()

        real_blocklist = log_to_blocklist(real_log_lines)
        emu_blocklist = log_to_blocklist(emu_log_lines)
        # print(f'\nreal_blocklist:{real_blocklist}')
        # print(f'emu_blocklist:{emu_blocklist}')
        #解析real_log_lines裡面 [Parent Block], [Child Block]的組合
        for i, real_block in enumerate(real_blocklist[:-1]):
            if '[Method END]\n' in real_block or ['[Method START]\n'] == real_block: #這種異常case不需要判斷下一個block
                continue
            real_child_block = real_blocklist[i+1]
            if real_child_block[0] == '[Method START]\n':#Method START不能當child
                continue

            emu_same_block = []
            for j, emu_block in enumerate(emu_blocklist[:-1]):
                if emu_block == real_block:
                    emu_same_block.append(j)
            if emu_same_block == []:#至少要有一樣的block才能比是否有evasion
                continue
     
            
            emu_child_blocks = [emu_blocklist[emu_index+1] for emu_index in emu_same_block if emu_blocklist[emu_index+1][0] != '[Method START]\n']
            # print(f'real_child_block:{real_child_block}')
            # print(f'emu_child_blocks:{emu_child_blocks}')
            if any(real_child_block[0] == emu_child_block[0] for emu_child_block in emu_child_blocks) or emu_child_blocks == []:
                continue #如果兩種裝置都走到一樣的child block(只要出現一次，只看開頭的TAG)那大概這個real_block就不是個evasion， 或是emu_child_block沒有動態執行到

            other_child_blocks = [real_blocklist[k+1] for k, real_same_block in enumerate(real_blocklist[:-1]) if real_same_block == real_block]
            # print(f'other_child_blocks:{other_child_blocks}')
            if any(real_child_block[0] != other_child_block[0] for other_child_block in other_child_blocks):
                continue #實體機應該要固定走同一個child block才可能是一個我們要的evasion
            
            #Evasion set加入不重複的evasion block
            if  {'location': basepath, 'block': real_block} not in evasion:
                evasion.append({'location': basepath, 'block': real_block})
                print(f'Find evasion:{real_block} belong to method:{basepath}, real_device_log_file:{real_device_log_file}, emu_device_log_file:{emu_device_log_file}')


    try:
        with open(os.path.join(app_logdir, 'evasion.json'), 'w') as f:
            for e in evasion:
                f.write(json.dumps(e)+'\n')
    except:
        pass

    return evasion
            
def split_log_lines(log_lines, is_emu, app_hash, conn, app_logdir, error_apps):
    # 用 method sign 和 random ID 組合作為區分
    discovered_method = defaultdict(list)
    method_hash_map = {}

    for line in log_lines:
        if app_hash not in line or 'SADroid' not in line:
            continue
        try:
            line_info = line.split(app_hash+'], ')[1]   
            method_hash, random_id = line_info.split(', [')[1].strip(']\n').split(']  $(')
            method_sign = conn.execute('SELECT method_sign FROM method WHERE method_hash =?', (method_hash,)).fetchone()

            if method_sign is None:
                continue
            method_sign = method_sign[0]
            method_hash_map[method_hash] = method_sign

            method_dir = os.path.join(app_logdir, method_hash)
            os.makedirs(method_dir, exist_ok=True)

            # 現在 discovered_method 包括 method_sign 和 random_id
            entry = (random_id, line_info.split(', [')[0])
            discovered_method[method_sign].append(entry)
        except Exception as e:
            print(f"Error processing line: {line}. Error: {e}")
            error_apps.add(app_logdir) 

    # 按 random ID 排序並寫入檔案
    for method_hash, method_sign in method_hash_map.items():
        method_dir = os.path.join(app_logdir, method_hash)
        log_file_name = 'emulator_device_log.txt' if is_emu else 'real_device_log.txt'
        log_file_path = os.path.join(method_dir, log_file_name)
        if method_sign in discovered_method:
            with open(log_file_path, 'w+') as log_file:
                # 排序
                sorted_entries = sorted(discovered_method[method_sign], key=lambda x: x[0])
                for _, line_info in sorted_entries:
                    log_file.write(line_info + '\n')
                log_file.write('\n')

# def build_dcfg(log_lines, is_emu, dcfg, app_hash, conn):
#     cur_block_key = {}#紀錄每個method建構中的basic block object在dcfg[method_sign]內的key，以防有多個執行續穿插的狀況
#     for line in tqdm(log_lines):
#         if app_hash not in line or 'SADroid' not in line:
#             continue
#         line_info = line.split(app_hash+'], ')[1]   
        
#         # get method sign from conn
#         # print(f'line_info:{line_info}')
#         method_hash = line_info.split(', [')[1].strip(']\n')
#         method_sign = conn.execute('SELECT method_sign FROM method WHERE method_hash =?', (method_hash,)).fetchone()

#         if method_sign is None:
#             # print(f'error method_sign:{method_sign}, method_hash:{method_hash}')
#             continue
#         method_sign = method_sign[0]
#         # print("method_sign:", method_sign)
#         if method_sign not in dcfg:
#             if '[Method START], [' not in line_info: # 若該method不存在於dcfg中，則必須是method start，不然可能是前面動態分析時logcat蒐集錯誤
#                 continue
#             dcfg[method_sign] = {
#                 'entry' : {
#                     'real_count' : 0 if is_emu else 1,
#                     'emu_count' : 1 if is_emu else 0,
#                 }
#             }
#             cur_block_key[method_sign] = 'entry'
#         else:#假設該method已經在DCFG內了
#             cur_method_dcfg = dcfg[method_sign]
#             if method_sign not in cur_block_key and not line_info.startswith('[Method START]'): #如果method_sign在cur_block_key中不存在，則必須是method start，不然可能是前面動態分析時logcat蒐集錯誤
#                 continue

#             if line_info.startswith('[Method START]'):#包含不存在於cur_block_key[method_sign]的情況 但可以直接重新指定
#                 if is_emu:
#                     cur_method_dcfg['entry']['emu_count'] += 1
#                 else:
#                     cur_method_dcfg['entry']['real_count'] += 1
#                 cur_block_key[method_sign] = 'entry' #假設不存在有同一個method 不同執行續 交錯執行的情況 所以遇到[Method START]就重設這個method的cur_block_key

#             elif line_info.startswith('[Branch: '):
#                 cur_method_dcfg[cur_block_key[method_sign]]['Branch'] = line_info.split('], [')[0][len('[Branch: '):]
#                 # print(f'cur_block_key:{cur_block_key} method_sign:{method_sign}  add branch')
            
#             elif line_info.startswith('[Method END]'):
#                 cur_method_dcfg[cur_block_key[method_sign]]['Return'] = True
#                 # print(f'cur_block_key:{cur_block_key} method_sign:{method_sign}  add return')

#             elif line_info.startswith('[TARGET API CALL: '): 
#                 api_info= line_info.split('], [')[0][len('[TARGET API CALL: '):]
#                 if 'Target API' not in cur_method_dcfg[cur_block_key[method_sign]]:
#                     cur_method_dcfg[cur_block_key[method_sign]]['Target API'] = [api_info]
#                 else:
#                     cur_method_dcfg[cur_block_key[method_sign]]['Target API'].append(api_info)
 
#             elif line_info.startswith('[TAG: '): #有同一個method內的新的basic block


#                 tag_info = line_info.split('], [')[0][len('[TAG: '):]
#                 if tag_info not in cur_method_dcfg: #新發現的block
#                     cur_method_dcfg[tag_info] = {
#                         'real_count' : 0 if is_emu else 1,
#                         'emu_count' : 1 if is_emu else 0,
#                     }
                    
#                 else: #重複累積次數                
#                     if is_emu:
#                         cur_method_dcfg[tag_info]['emu_count'] += 1
#                     else:
#                         cur_method_dcfg[tag_info]['real_count'] += 1
#                         c = cur_method_dcfg[tag_info]['real_count']
#                         # print(f'TAG real_count:{c}')

#                 last_block = cur_block_key[method_sign]
#                 new_child_trace = {
#                     'real_count' : 0 if is_emu else 1,
#                     'emu_count' : 1 if is_emu else 0,
#                 }
#                 # if 'parent block' not in cur_method_dcfg[tag_info]:
#                 #     cur_method_dcfg[tag_info]['parent block'] = {last_block : new_child_trace}
#                 # elif last_block not in cur_method_dcfg[tag_info]['parent block'].keys():
#                 #     cur_method_dcfg[tag_info]['parent block'][last_block] = new_child_trace
#                 # else:
#                 #     if is_emu:
#                 #         cur_method_dcfg[tag_info]['parent block'][last_block]['emu_count'] += 1
#                 #     else:
#                 #         cur_method_dcfg[tag_info]['parent block'][last_block]['real_count'] += 1
#                 #         c = cur_method_dcfg[tag_info]['parent block'][last_block]['real_count']
#                 #         print(f'TAG parent block real_count:{c}')
#                 if 'child block' not in cur_method_dcfg[last_block]:#指定上一個的child block指向現在這個TAG                    
#                     cur_method_dcfg[last_block]['child block'] = {tag_info : new_child_trace}
#                 elif tag_info not in cur_method_dcfg[last_block]['child block'].keys():#這個child tag還沒被記錄過
#                     cur_method_dcfg[last_block]['child block'][tag_info] = new_child_trace
#                 else: #tag_info已經是其中一個已知的child block了 增加軌跡紀錄
#                     if is_emu:
#                         cur_method_dcfg[last_block]['child block'][tag_info]['emu_count'] += 1
#                     else:
#                         cur_method_dcfg[last_block]['child block'][tag_info]['real_count'] += 1
#                         c = cur_method_dcfg[last_block]['child block'][tag_info]['real_count']
#                         # print(f'TAG child block real_count:{c}, last_block:{last_block}, tag_info:{tag_info}')
                    
#                 # input(f'cur_block_key key:{cur_block_key[method_sign]} value:{cur_method_dcfg[cur_block_key[method_sign]]}')    
#                 #找出在cur_method_dcfg裡面對應 cur_block_key[method_sign]的key


#                 cur_block_key[method_sign] = tag_info
#                 # input(f'check cur_method_dcfg[{tag_info}]:{cur_method_dcfg[tag_info]}')

#                 # print(f'cur_block_key:{cur_block_key} method_sign:{method_sign} add tag:{tag_info}')
                

if __name__ == "__main__":
    # 創建或打開數據庫
    error_apps = set()
    logcat_dir = './logcat'
    dcfg_dir = './dcfg' 
    with open('./jsons/TriggerZoo_x86_filename2packagename.json', 'r') as f:
        f2p_mapping = json.load(f)
    
    dbfile = "data.db"
    conn = sqlite3.connect(dbfile)
    all_devices = get_available_devices()
    total_evasion = []
    for app_name in tqdm(os.listdir(logcat_dir)):
        print(f'app name:{app_name}')
        package_name = f2p_mapping[app_name]
        app_hash = hash_sign(app_name)
        print(f'app hash:{app_hash}, package_name:{package_name}')

        app_logdir = os.path.join(dcfg_dir, package_name)
        if not os.path.exists(app_logdir):
            os.makedirs(app_logdir)
        # dcfg_file = os.path.join(dcfg_dir, package_name+'_dcfg.json')

        # if os.path.exists(dcfg_file): 
        #     with open(dcfg_file, 'r') as f:
        #         dcfg = json.load(f)
        # else:
        #     dcfg = {}

        for log_file in os.listdir(os.path.join(logcat_dir, app_name)):
            if '_logcat_output' not in log_file: #only the main output of SADroid
                continue
            
            is_emu = True if 'emulator' in log_file else False
            with open(os.path.join(logcat_dir, app_name, log_file), 'r') as f:
                log_lines = f.readlines() 
            split_log_lines(log_lines, is_emu, app_hash, conn, app_logdir, error_apps)



            # build_dcfg(log_lines, is_emu, dcfg, app_hash, conn)

        #分析app_logdir裡面每一個method的資料夾



        evasion = find_evasion(app_logdir, conn)
        print(f'app_name:{app_name}, evasion:{evasion}')
        total_evasion += evasion
    print(f'Total evasion:{total_evasion}')
    print("Apps that raised errors:")
    for app_name in error_apps:
        print(app_name)

        # #write dcfg file to json
        # with open(dcfg_file, 'w') as f:
        #     json.dump(dcfg, f, indent=4)
        # input(f'dcfg:{dcfg}')


