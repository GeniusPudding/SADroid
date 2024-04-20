#主要放產生要注入的smali語法的地方
import os
import argparse
#from .apk_utils import *
from .smali_parser import *
import random
import json
import sys
import re
from functools import reduce
official_lib_prefix = ['android','androidx', 'kotlin', 'kotlinx', 'java', 'javax','dalvik','junit', 'org']#['android','androidx', 'kotlin', 'kotlinx', 'java', 'javax','dalvik','junit','android_maps_conflict_avoidance','io','org','okhttp3','okio','sun','libcore']
com_list = ['android','facebook','google', 'adobe']
get_invoke_sign = lambda line: line.strip().split(', ')[-1].strip()
get_common_invoke_regs = lambda line: line[line.index('{')+1:line.index('}')].split(', ') if not '{}' in line else []
preg_move_offset = lambda new_range_end_reg, offset, locals_num: 'p'+ str(int(new_range_end_reg[1:])-offset) if int(new_range_end_reg[1:]) > 1 else 'v' + str(int(new_range_end_reg[1:])+locals_num-offset)#算一下是v型還是p型
next_reg = lambda reg: reg[0] + str(int(reg[1:])+1)
#lambda function for p-form register to v-form register
p2v_reg = lambda reg, locals_num: 'v' + str(int(reg[1:])+locals_num) if reg[0] == 'p' else reg
tag_sign = lambda line: line.strip().lstrip(':') if not ':cond_' in line else 'True'+line.strip()
additional_local_count = 2
def check_common_instruction_replace(line, locals_num):
	if not notCommonInstruction(line):
		try:
			return replace_p_to_v_in_line(line, locals_num)
			
		except Exception as e:
			print(f'解析指令異常:{e}')
			return line
	else:
		return line

def replace_p_to_v_in_line(line, locals_num):
	# 首先匹配 invoke-xxx/range 的格式
	range_matches = re.findall(r'\{p(\d+) \.\. p(\d+)\}', line)
	for start, end in range_matches:
		v_start = p2v_reg('p' + start, locals_num)
		v_end = p2v_reg('p' + end, locals_num)
		line = line.replace(f'{{p{start} .. p{end}}}', f'{{{v_start} .. {v_end}}}')
	# 再匹配普通的 pX 格式
	p_regs = re.findall(r'\bp\d+\b', line)
	for reg in p_regs:
		v_reg = p2v_reg(reg, locals_num)
		line = re.sub(r'\b' + reg + r'\b', v_reg, line)
	return line

def not_exist_in_path(method_sign,smali_base_dir):	#如果該smali file存在也必須掃一次看是否目標method存在 (避免虛方法)
	try:
		dir_list = get_dirlist(method_sign)[:-1]#先取class dir
	except:
		return True
	#print(f'method_sign:{method_sign}, smali_base_dir:{smali_base_dir}')
	smali_path = ''
	tmp = method_sign.split('->')
	
	class_name, method_name = tmp[0], tmp[-1]
	#print(f'method_sign:{method_sign}, dir_list:{dir_list}')
	not_exist = False
	apk_dir = os.path.dirname(smali_base_dir.rstrip('/'))
	#current_base = smali_base_dir
	for d in [d for d in os.listdir(apk_dir) if d.startswith('smali')]:#在multidex的情況必須看完每一個smali dir
		current_base = os.path.join(apk_dir,d)
		not_exist = False
		for dir in dir_list[:-1]: #dir_list[-1]是class name 但有可能跟檔名不一樣 所以這邊先排除
			new_cur = os.path.join(current_base,dir)
			#print(f'new_cur:{new_cur}')

			if not os.path.isdir(new_cur):
				not_exist = True #這個class路徑根本不存在 不用跑後面class name的部分 直接去看下一個dex
				break
			current_base = new_cur
		#print(f'current_base:{current_base}, not_exist:{not_exist}, class_name:{class_name}, method_name:{method_name} ')
		if not not_exist:#觀察最後一層目錄內所有的smali 如果有跟class name符合的就設為smali_path
			smalis = [s for s in os.listdir(current_base) if s[-6:] == '.smali']
			#print(f'smalis:{smalis}')
			for s in smalis:
				#print(f's:{s}')
				t = os.path.join(current_base, s)
				#print(f't:{t}, exists:{os.path.exists(t)}')
				with open(t, 'r',encoding='utf-8') as f:
					line = f.readline()
					#print(f'line:{line}')
					if line.strip().split(' ')[-1] == class_name:
						#input(f'line:{line},class_name:{class_name}')
						smali_path = os.path.join(current_base, s)
						#print(f'smali_path:{smali_path}')
						break
			else:
				#input(f'class_name:{class_name}')
				not_exist = True #這個smali class檔案根本不存在 不用跑後面的讀檔 直接去看下一個dex

		if not not_exist: #如果有這個class (current_base剛好是class name
			#smali_path = current_base + '.smali'
			try:
				with open(smali_path, 'r', encoding="utf-8" ) as f:
					not_exist = not any([m_def for m_def in f.readlines() if m_def.startswith('.method') and method_name in m_def])

			except:
				input(f'current_base:{current_base},method_sign:{method_sign},exist:{not not_exist},dir_list:{dir_list}')	
		if not not_exist: return not_exist #
	return not_exist



def is_invoke_offcial(invoke_line):#黑名單 但不知道要怎樣才會齊全
	is_offcial = False
	sign = get_invoke_sign(invoke_line)
	dir_list = sign[1:].split(';->')[0].split('/')
	if dir_list[0] in official_lib_prefix or (dir_list[0] == 'com' and dir_list[1] in  com_list):
		is_offcial = True
	return is_offcial

def gen_method_start_log(method_hash, v_last, v_last2, app_hash):	
	#new_content = ('    #Instrumentation by GeniusPudding\n')
	new_content = (f'    invoke-static {{}}, LSADroid/InlineLogs;->genRandom()Ljava/lang/String;\n\n')
	new_content += (f'    move-result-object {v_last2}\n\n')
	new_content += (f'    const-string {v_last}, \"[{app_hash}], [Method START], [{method_hash}] \"\n\n')
	new_content += (f'    invoke-static/range {{{v_last} .. {v_last2}}}, LSADroid/InlineLogs;->stringCancate(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n\n')
	new_content += (f'    move-result-object {v_last}\n\n')
	new_content += (f'    invoke-static/range {{{v_last}}}, LSADroid/InlineLogs;->monitorLog(Ljava/lang/String;)V\n\n')

	return new_content

# function for generating the correspounding move- instructions in smali of parameters "params_list"
def gen_method_params_log(locals_num, params_list):
	if len(params_list) == 0:
		return ''	
	new_content = ('    #Instrumentation by GeniusPudding\n')
	p_count = 0
	for param in params_list:
		p_reg = f'p{p_count}'
		v_reg = p2v_reg(p_reg, locals_num)
		#param types: value, wide-value, object (using move/16, move-wide/16, move-object/16)
		if param == 'J' or param == 'D':
			new_content += (f'    move-wide/16 {v_reg}, {p_reg}\n\n')
			p_count += 1
		elif len(param) == 1:
			new_content += (f'    move/16 {v_reg}, {p_reg}\n\n')
		else:
			new_content += (f'    move-object/16 {v_reg}, {p_reg}\n\n')

		p_count += 1
	return new_content

def method_logger(smali_lines,smali_base_dir, target_API_graph_all, app_hash, cursor):
	in_excluded_method = False	
	in_method_flag = False
	output_flag = 1
	class_name = smali_lines[0].split(' ')[-1].strip('\n')
	if smali_lines[0].startswith('.class public interface abstract'):# 
		#這些裡面應該都是abstract method，可忽略
		return ''.join(smali_lines)
	current_method_signature = '' 
	method_hash = ''
	has_method = False
	new_content = ''
	locals_num = 0
	params_num = 0
	v_last = '' #用來存放要Logcat輸出的訊息字串
	v_last2 = '' #用來存放random ID的暫存register
	params_list = []

	for i,line in enumerate(smali_lines):
		tmp_line = line
		if line.startswith('.method ') and '<clinit>(' not in line :# and (not target_methods or any([m in line for m in target_methods])): #
			in_method_flag = True
			_splitted_identifiers = line.strip('\n').split(' ')
			current_method_signature = f'{class_name}->' + _splitted_identifiers[-1]
			method_hash = hash_sign(current_method_signature)
			cursor.execute('INSERT OR IGNORE INTO method (method_hash, method_sign, app_hash) VALUES (?, ?, ?)', (method_hash, current_method_signature, app_hash))
    
			locals_num = 0	
			params_list = get_params_list(line, class_name)
			params_num = param_registers_num(params_list)#已經考慮了J、D type的長度

		elif in_method_flag:#method analysis
			line = line.strip('\n')	
			line = check_common_instruction_replace(line, locals_num-additional_local_count)
			if line.startswith('    .locals '):
				locals_num  = int(line.split(' ')[-1])
				#如果locals_num大於254就不改寫這個method了
				if locals_num > 255:
					new_content += ''.join(smali_lines[i:])
					return new_content
				num = locals_num + params_num
				v_last = 'v'+str(num)
				v_last2 = 'v'+str(num + 1)
				line = line.replace(str(locals_num),str(locals_num+additional_local_count))
				new_content += (line+'\n')
				new_content += gen_method_params_log(locals_num, params_list)
				new_content += gen_method_start_log(method_hash, v_last, v_last2, app_hash)
				locals_num += additional_local_count
				output_flag = 0 
			elif line.startswith('.end method'):
				in_method_flag = False
				#try_catch_map = {}
			elif line.startswith('    return'):
				new_content += (f'    const-string {v_last}, "[{app_hash}], [Method END], [{method_hash}] "\n\n')
				new_content += (f'    invoke-static/range {{{v_last} .. {v_last2}}}, LSADroid/InlineLogs;->stringCancate(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n\n')
				new_content += (f'    move-result-object {v_last}\n\n')
				new_content += (f'    invoke-static/range {{{v_last}}}, LSADroid/InlineLogs;->monitorLog(Ljava/lang/String;)V\n\n')
			elif line.startswith('    invoke'):
				invoke_sign = get_invoke_sign(line)
				if is_target_method(invoke_sign,smali_base_dir,target_API_graph_all):
					new_content += (f'    const-string {v_last}, \"[{app_hash}], [TARGET API CALL: {invoke_sign} - (line {str(i)})], [{method_hash}] \"\n\n')
					new_content += (f'    invoke-static/range {{{v_last} .. {v_last2}}}, LSADroid/InlineLogs;->stringCancate(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n\n')
					new_content += (f'    move-result-object {v_last}\n\n')
					new_content += (f'    invoke-static/range {{{v_last}}}, LSADroid/InlineLogs;->monitorLog(Ljava/lang/String;)V\n\n')

			elif line.startswith('    if-'):
				output_flag	= 0
				new_content += (f'    const-string {v_last}, \"[{app_hash}], [Branch: {tmp_line.strip()} - (line {str(i)})], [{method_hash}] \"\n\n')
				new_content += (f'    invoke-static/range {{{v_last} .. {v_last2}}}, LSADroid/InlineLogs;->stringCancate(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n\n')
				new_content += (f'    move-result-object {v_last}\n\n')
				new_content += (f'    invoke-static/range {{{v_last}}}, LSADroid/InlineLogs;->monitorLog(Ljava/lang/String;)V\n\n')
				new_content += (line+'\n\n')
				# new_content += (f'    const-string {v_last}, \"- Case False: {line.strip()}\"\n\n')
				false_tag = 'False'+line.strip().split(' ')[-1]
				new_content += (f'    const-string {v_last}, \"[{app_hash}], [TAG: {false_tag} - (line {str(i)})], [{method_hash}] \"\n\n')
				new_content += (f'    invoke-static/range {{{v_last} .. {v_last2}}}, LSADroid/InlineLogs;->stringCancate(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n\n')
				new_content += (f'    move-result-object {v_last}\n\n')
				new_content += (f'    invoke-static/range {{{v_last}}}, LSADroid/InlineLogs;->monitorLog(Ljava/lang/String;)V\n')
			# elif line.startswith('    move-result'):
			# 	pass
			elif line.startswith('    move-exception'):#都給前一行出現的標籤處來輸出
				output_flag	= 0
			# elif line.startswith('    goto'):
			# 	tag = line.strip().split(' ')[-1]
			# 	new_content += (f'    const-string {v_last}, \"[{app_hash}], [Goto: line:{str(i)}, {current_method_signature} {tag}\"\n\n')
			# 	new_content += (f'    invoke-static/range {{{v_last}}}, LSADroid/InlineLogs;->monitorLog(Ljava/lang/String;)V\n\n')
			
			elif line.startswith('    :'):#去注入ㄧ些分支跳轉相關的標籤, cond, goto, try_start 有時候會連在一起 很麻煩
				output_flag = 0
				last_line = smali_lines[i-1]
				if not last_line.startswith('    :'):# 若上一行也是標籤，則表示這個標籤已經處理過了
			
					next_line = check_common_instruction_replace(smali_lines[i+1], locals_num-additional_local_count)
					next2_line = check_common_instruction_replace(smali_lines[i+2], locals_num-additional_local_count) #標籤後面緊接的指令必須妥善處理
					tag_str = f'[{app_hash}], [TAG: '
					if line.startswith('    :try_end'):
						catch_list = next_line.strip().split(' ')	 #    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
						end, catch = catch_list[-2][1:-1], catch_list[-1][1:]
						tag_str += (end + '->:' + catch + f' - (line {str(i)})], [{method_hash}] ')
						new_content += (f'    const-string {v_last}, \"{tag_str}\"\n\n')
						new_content += (f'    invoke-static/range {{{v_last} .. {v_last2}}}, LSADroid/InlineLogs;->stringCancate(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n\n')
						new_content += (f'    move-result-object {v_last}\n\n')
						new_content += (f'    invoke-static/range {{{v_last}}}, LSADroid/InlineLogs;->monitorLog(Ljava/lang/String;)V\n\n')				
						new_content += (line+'\n')
					elif line.startswith('    :sswitch_data') or line.startswith('    :pswitch_data') :# 這個下一行會跟著.sparse-switch或.packed-switch [offset]然後是一堆case
						new_content += (line+'\n')
					elif line.startswith('    :array'):
						new_content += (line+'\n')
					elif line.startswith('    :catch'):#:catch, :catchall
						new_content += (line+'\n')
						new_content += next_line
						if next_line.startswith('    :'): #try_start會接後面 :catchall後面也會接:cond
							new_content += next2_line
						tag_str += (tag_sign(line) + f' - (line {str(i)})], [{method_hash}] ')
						new_content += (f'\n    const-string {v_last}, \"{tag_str}\"\n\n')
						new_content += (f'    invoke-static/range {{{v_last} .. {v_last2}}}, LSADroid/InlineLogs;->stringCancate(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n\n')
						new_content += (f'    move-result-object {v_last}\n\n')
						new_content += (f'    invoke-static/range {{{v_last}}}, LSADroid/InlineLogs;->monitorLog(Ljava/lang/String;)V\n\n')										
					else: # common tag case
						new_content += (line+'\n')
						tag_str += tag_sign(line)
						if next_line.startswith('    :'):
							new_content += next_line
							tag_str += (','+tag_sign(next_line))
							if next2_line.startswith('    :'):
								new_content += next2_line
								tag_str += (','+tag_sign(next2_line))
						tag_str += f' - (line {str(i)})], [{method_hash}] '
						new_content += (f'    const-string {v_last}, \"{tag_str}\"\n\n')
						new_content += (f'    invoke-static/range {{{v_last} .. {v_last2}}}, LSADroid/InlineLogs;->stringCancate(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n\n')
						new_content += (f'    move-result-object {v_last}\n\n')
						new_content += (f'    invoke-static/range {{{v_last}}}, LSADroid/InlineLogs;->monitorLog(Ljava/lang/String;)V\n\n')				
			line += '\n'	
		if output_flag:
			new_content += line
		else:
			output_flag = 1	

	if not has_method:
		return new_content
	return new_content

def walk_smali_dir(smali_base_dir, target_API_graph_all, app_hash, cursor, log_mode = True):#default mode: Logging

	walking_list = []
	for d in os.listdir(smali_base_dir):
		if d in official_lib_prefix:#system API
			continue

		if d == 'com':#處理一下特殊情況 忽略ㄧ些com底下的
			for dd in os.listdir(os.path.join(smali_base_dir,'com')): 
				if dd in com_list:
					continue
				#print(f'dd:{dd}')
				w = list(os.walk(os.path.join(smali_base_dir,'com',dd)))
				if len(w) > 0:
					walking_list += w#list(os.walk(os.path.join(smali_base_dir,'com',dd)))
		else:	
			#print(f'd:{d}')
			w = list(os.walk(os.path.join(smali_base_dir,d)))
			if len(w) > 0:
				walking_list += w#list(os.walk(os.path.join(smali_base_dir,d)))

	#for the instrumentation
	if not log_mode:
		read_signs_set = set()
	#input(f'walking_list:{walking_list}')
	for i, walking_tuple in enumerate(walking_list):
		if len(walking_tuple[2]) == 0:
			continue
		#print(f'walking_tuple:{walking_tuple},log_mode:{log_mode}')
		for file_name in walking_tuple[2]:
			if file_name[-6:] != '.smali':
				continue

			# start to parse the smali files
			full_name = os.path.join(os.path.abspath(walking_tuple[0]),file_name)
			if log_mode:
				try:
					f = open(full_name,'r+', encoding='utf-8')
					smali_lines = list(f)

					f.seek(0)
				except Exception as e:#這有必要嗎
					input(f"method_logger Error: e:{e},full_name:{full_name}")
					#input(f'smali_lines:{smali_lines}')
				new_content = method_logger(smali_lines, smali_base_dir, target_API_graph_all, app_hash, cursor)
				f.write(new_content)
				f.close()
			else:
				f = open(full_name,'r', encoding='utf-8')
				read_signs_set.update({get_invoke_sign(line)   for line in f.readlines() if line.startswith('    invoke-')})

	if not log_mode:
		return read_signs_set	
