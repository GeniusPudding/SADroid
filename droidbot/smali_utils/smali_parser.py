#解析smali語法的功能都可以放這


import re
from rich.console import Console
import hashlib
console = Console()
param_registers_num = lambda params_list: len(params_list) + params_list.count('J') + params_list.count('D')
get_dirlist = lambda method_sign: method_sign[1:].split(';->')[0].split('/') + [method_sign[1:].split(';->')[1].split('(')[0]]

is_main_activity = lambda class_name, main_activity: class_name[1:-1].split('/') == main_activity.split('.')
# entry_list = ['onCreate(Landroid/os/Bundle;)V', "onStart()V", 'onRestart()V',"onResume()V",  "onPause()V", "onStop()V", "onDestroy()V"\
#      ,'onStart(Landroid/content/Intent;I)V',  'onStartCommand(Landroid/content/Intent;II)I', "onReceive(Landroid/content/Context;Landroid/content/Intent;)V"]  
#lifecycle methods
pattern = r'[0-9]'
# function: use regex to filter out all numbers of the method sign string sha256 result, and return
get_mspace_fieldname = lambda method_sign: re.sub(pattern, '', hashlib.sha256(method_sign.encode('utf-8')).hexdigest())
hash_sign = lambda sign: hashlib.sha256(sign.encode('utf-8')).hexdigest()[:16] # use 16 chars to identify
 

def get_params_list(line,  class_sign = None):#.method 或是invoke line, .method需要額外傳入class_sign
    
    if line.startswith('.method'):
        is_static = 'static' in line.split(' ')
        #print(f'line:{line},is_static:{is_static}')
        if not class_sign: raise ValueError(f'method line:{line} has no class_sign')
    elif line.startswith('    invoke'):
        is_static = line.startswith('    invoke-static')
        class_sign = line.split('->')[0].split(' ')[-1]
    else:
        raise ValueError(f'line:{line} has no param string')
    param_string = line[line.index('(')+1:line.index(')')]
 
    params_list = []
    #print(f'param_string:{param_string}')
    if param_string == '':
        return [] if is_static else [class_sign]
    partitions_id = []
    l = len(param_string)
    in_class = False 
    i = 0
    while i < l:
        if param_string[i] == 'L':
            in_class = True
        if in_class:
            if param_string[i] == ';':
                in_class = False
                partitions_id.append(i)
            #else: class name and path, ignored
        else:
            if param_string[i] != '[':
                partitions_id.append(i)
        i = i + 1

    last_p = 0
    for p in partitions_id:
        params_list.append(param_string[last_p:p+1])
        last_p = p + 1
    if not is_static:
        params_list = [class_sign] + params_list

    return params_list

def get_param_types(params_list,params_num):#params_num也可以用param_registers_num
	param_types = ['value']*params_num
	#print(f'init param_types:{param_types}')
	_param_index = 0
	for param in params_list: 
		if param == 'J' or param == 'D':
			_param_index += 2
		else:
			if len(param) > 1:
				param_types[_param_index] = 'object'
			_param_index += 1	
	return param_types

def get_invoke_range_regs(invoke_line, locals_num, register_case):#把range實際呼叫用的arguments所在的register抓出來 (考慮到已經被插一個locals在末端)
	#print(f'invoke_line:{invoke_line}')
	invoke_regs = invoke_line[invoke_line.index('{')+1:invoke_line.index('}')].split(' .. ')
	actual_regs = []
	start, end = invoke_regs[0], invoke_regs[1]
	offset = 0 #如果是v-p這種需要搬動暫存器內容吧 range必須是連號
	s_i, e_i = int(start[1:]), int(end[1:])	

	if  start[0] == 'p' and  end[0] == 'p':#沒有offset
		for i in range(s_i,e_i+1):
			actual_regs.append('p'+str(i)) 
                  
	else:
		locals_num -= (2 if register_case == 2 else 1) #扣掉offset算回原本的locals_num
		if end[0] == 'v' and int(end[1:]) < locals_num: #v form且<locals num
			for i in range(s_i,e_i+1):
				actual_regs.append('v'+str(i)) 
		else:
			offset = 2 if register_case == 2 else 1
			for i in range(s_i, locals_num):
				actual_regs.append('v'+str(i))			
			if end[0] == 'p':    
				for i in range(e_i+1):	
					actual_regs.append('p'+str(i))
			else: # (end[0] == 'v' and int(end[1:]) >= locals_num):#剩下兩種都有可能因為加了locals而斷掉range
				for i in range(locals_num+offset,  e_i+2):	
					actual_regs.append('v'+str(i))   

	# if offset > 0:
	# 	input(f'actual_regs:{actual_regs}, offset:{offset},locals_num:{locals_num}')
	return actual_regs, offset

def get_invoke_range_regs_ver2(invoke_line, locals_num):#把range實際呼叫用的arguments所在的register抓出來 (考慮到已經被插一個locals在末端)
	#print(f'invoke_line:{invoke_line}')
	invoke_regs = invoke_line[invoke_line.index('{')+1:invoke_line.index('}')].split(' .. ')
	actual_regs = []
	start, end = invoke_regs[0], invoke_regs[1]
	offset = 0 #如果是v-p這種需要搬動暫存器內容吧 range必須是連號
	s_i, e_i = int(start[1:]), int(end[1:])	

	if  start[0] == 'p' and  end[0] == 'p':#沒有offset
		for i in range(s_i,e_i+1):
			actual_regs.append('p'+str(i)) 
                  
	else:
		if end[0] == 'v' and int(end[1:]) < locals_num: #v form且<locals num
			for i in range(s_i,e_i+1):
				actual_regs.append('v'+str(i)) 
		else:
			for i in range(s_i, locals_num):
				actual_regs.append('v'+str(i))			
			if end[0] == 'p':    
				for i in range(e_i+1):	
					actual_regs.append('p'+str(i))
			else: # (end[0] == 'v' and int(end[1:]) >= locals_num):#剩下兩種都有可能因為加了locals而斷掉range
				for i in range(locals_num+offset,  e_i+2):	
					actual_regs.append('v'+str(i))   

	return actual_regs

def get_registers_usage_in_line(dalvik_bytecode_line): 
    #Check for all dalvik instructions in smali representation or androguard representation
    def parse_smali_tokens(dalvik_bytecode_line):
        #input: dalvik_bytecode_line needs to be a valid DVM instruction
        #output: intruction name, register list
        # console.print(f'dalvik_bytecode_line:[green bold]{dalvik_bytecode_line}[/green bold]')
        dalvik_bytecode_line = dalvik_bytecode_line.strip()
        
        try:#parsing the smali syntax
            # console.print(f'dalvik_bytecode_line:[green bold]{dalvik_bytecode_line}[/green bold]')
            smali_tokens = dalvik_bytecode_line.split(' ')
            # console.print(f'smali_tokens:[green bold]{smali_tokens}[/green bold]')
            instruction = smali_tokens[0]
            # console.print(f'instruction:[green bold]{instruction}[/green bold]')
            if 'range' in instruction:
                if len(smali_tokens) == 3: #invoke-virtual/range v16, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;
                    return instruction, [smali_tokens[1]]
                fromreg = smali_tokens[1].strip('{')
                toreg = smali_tokens[3].strip(',}')
                reg_list = [toreg]
                prefix = fromreg[0]
                fromindex = int(fromreg[1:])
                toindex = int(toreg[1:])
                for index in range(fromindex,toindex):
                    reg_list.append(prefix+str(index))
                return instruction, reg_list
            if '<init>' in dalvik_bytecode_line:
                instruction += ' <init>'
            # console.print(f'smali_tokens:[green bold]{smali_tokens}[/green bold]')
            if len(smali_tokens)>1:
                
                register_form = smali_tokens[1:]
                #need to find out if the last part is a register or class description
                register_re =re.compile(r'^[vp][0-9]+$')
                reg_list = register_form = [ r.strip('\{\},') for r in register_form]
                # print(f'register_form:{register_form}')

                for i in range(len(register_form)):
                    if not re.match(register_re, register_form[i]):
                        reg_list = register_form[:i]
                        break
                
                if '' in reg_list:
                    reg_list.remove('')
            else:
                reg_list = []

        except:
            raise ValueError(f'Not supported instruction: {dalvik_bytecode_line}')
        return instruction, reg_list	

    instruction,reg_list = parse_smali_tokens(dalvik_bytecode_line)
    #print(f'reg_list:{reg_list}')
    result_regs = []
    operand_regs = []
    result_types = []
    if reg_list == []:
        return operand_regs,result_regs, result_types

    try:
        if any([i in instruction for i in ['nop','void','goto']]):
            return #instruction with no register
        if any([i in instruction for i in ['return','check','filled','throw', 'switch', 'if-','put','invoke']]):#先把沒有destination register的指令挑出(再處理例外)
            #these ins have no target register, except for put- ins
            operand_regs = reg_list.copy()
            if 'put' in instruction: #'aput', 'iput', 'sput'     
                if 'aput' in instruction or 'iput' in instruction:#sput也沒有輸出register
                    result_regs = [reg_list[1]]
                    if 'iput' in instruction and not 'object' in instruction:
                        result_types = ['value']
                    else:
                        result_types = ['object']
                    reg_list.remove(reg_list[1])
                if 'wide' in instruction:
                    operand_regs.append(operand_regs[0][0]+str(int(operand_regs[0][1:])+1))	#next order reg	                               
                    
            elif 'invoke' in instruction:#Maybe sometimes influences the obj register 
                if '<init>' in instruction:
                    result_regs = [reg_list[0]]
                    result_types = ['object']

            elif 'return-wide' in instruction :
                operand_regs.append(operand_regs[0][0]+str(int(operand_regs[0][1:])+1))	#next order reg	             
            
        else:  
            result_regs = [reg_list[0]]  #把都是第一個register作為output的指令放在這
            result_types = ['value']
            
            if  'const' in instruction: #any([i in instruction for i in ['const','fill-array-data']]):#or others
                if any([i in instruction for i in ['object','class' ,'string']]): 
                    result_types = ['object']
                # else:
                #     result_types = ['value']
                if 'wide' in instruction: 
                    result_regs.append(result_regs[0][0]+str(int(result_regs[0][1:])+1))	#next order reg           
                    result_types.append('value')     
            elif 'new-' in instruction:#new-instance, new-array	
                operand_regs = reg_list[1:]
                result_types = ['object']
            elif 'fill-array-data' == instruction:
                operand_regs = [reg_list[0]]
                result_types = ['object']
            elif 'array' in instruction:#還有其他的指令目前有點看不懂
                operand_regs = [reg_list[1]]
                if 'new-array' == instruction:                    
                    result_types = ['object']  
                elif 'array-length' == instruction:
                    result_types = ['value']  
            elif 'get' in instruction:
                #sget-{} vx,field_id;  #iget-{} vx,vy,field_id;  #aget-{} vx,vy,vz
                if 'object' in instruction: 
                    result_types = ['object']
                operand_regs = reg_list[1:]
                if 'wide' in instruction: 
                    result_regs.append(result_regs[0][0]+str(int(result_regs[0][1:])+1))	#next order reg  
                    result_types.append('value')  
            elif 'move' in instruction:#move, move-result
                if not '-result' in instruction and not '-exception' in instruction:#一般的move
                    operand_regs = [reg_list[1]]
                if 'object' in instruction or '-exception' in instruction: 
                    result_types = ['object']
                if 'wide' in instruction: 
                    if 'result' not in instruction:#'move-result-wide' has no operand_regs
                        operand_regs.append(operand_regs[0][0]+str(int(operand_regs[0][1:])+1))	#next order reg	 
                    result_regs.append(result_regs[0][0]+str(int(result_regs[0][1:])+1))	#next order reg	 
                    result_types.append('value')
            elif 'monitor' in instruction:#monitor-enter v3, monitor-exit v3
                operand_regs = reg_list.copy()
            elif 'instance-of' in instruction:
                operand_regs = [reg_list[1]]
            elif 'cmp' in instruction:#cmpl-float, cmpg-double, ...
                operand_regs = reg_list[1:]
                if '-double' in instruction:#How about cmp-long??? Not mentioned in doc
                    operand_regs.append(operand_regs[0][0]+str(int(operand_regs[0][1:])+1))	#next order reg	
                    operand_regs.append(operand_regs[1][0]+str(int(operand_regs[1][1:])+1))	#next order reg	
            elif '-to-' in instruction or 'neg-' in instruction or 'not-' in instruction: #unary operation
                operand_regs = [reg_list[1]]
                if '-double' in instruction or '-long' in instruction:
                    result_regs.append(result_regs[0][0]+str(int(result_regs[0][1:])+1))	#next order reg	
                    result_types.append('value')
                elif 'double-' in instruction or 'long-' in instruction:
                    operand_regs.append(operand_regs[0][0]+str(int(operand_regs[0][1:])+1))	#next order reg	
            elif any([i in instruction for i in ['add-','sub-','mul-','div-','rem-','or-','and-','shr-','shl-']]) :  #binary operation
                if '/2addr' in instruction:#first reg is also an operand and destination
                    operand_regs = reg_list.copy()
                else: #2or3 regs, such as sub-long, add-int/lit8 
                    operand_regs = reg_list[1:]	
                if '-double' in instruction or '-long' in instruction:
                    result_regs.append(result_regs[0][0]+str(int(result_regs[0][1:])+1))	#next order reg	
                    result_types.append('value')
                    operand_regs.append(operand_regs[0][0]+str(int(operand_regs[0][1:])+1))	#next order reg		
                    if 	len(reg_list) > 2:
                        operand_regs.append(operand_regs[1][0]+str(int(operand_regs[1][1:])+1))	#next order reg	

    except:
        input(f'Exception instruction:{instruction},reg_list:{reg_list}')
    return operand_regs,result_regs,result_types#src,dest
def notCommonInstruction(smali_line):
    return any([smali_line.startswith(e) for e in ['    .','    :','    #','.','     ']]) or smali_line.strip() == ''
	
def is_4bit_instruction(line):
    ins = line.strip().split(' ')[0]
    if any([line.startswith(prefix) \
        for prefix in ['    return', '    move-result', '    const ', '    const-wide', '    monitor', '    check-', \
            '    new-instance', '    throw', '    cmp', '    fill-']]) \
        or any([substr in ins for substr in ['/16', '/from16', 'range', 'switch']])\
        or (line.startswith('if-') and 'z' in ins)\
        or (('put' in ins or 'get' in ins) and not ins.startswith('i'))\
        or (any([line.startswith(prefix) for prefix in ['    add', '    sub', '    mul', '    div', '    rem', '    and', \
            '    or', '    xor', '    shl', '    shr', '    ushr']]) and not '2addr' in ins and not 'lit16' in ins) :
        return False
    return True

def p_reg_to_v(p_reg,locals_num):
	#if locals_num = 2, v2 = p0
	if p_reg[0]=='p':
		return 'v' + str(int(p_reg[1:])+locals_num)
	elif p_reg[0]=='v':  		
		return	p_reg
	else:
		raise ValueError('Wrong register name')

def is_target_method(method_sign,smali_base_dir,target_API_graph_all):#TODO TriggerMethod重複算了 照理說有包含在apk內
	# 應該看target method就好, 把native method考慮進去
	#print(f'invoke:{method_sign}')
	
	try:
		dir_list = get_dirlist(method_sign)
	except:
		return False
	boolean = True
	current_dict = target_API_graph_all
	#print(f'dir_list:{dir_list}')
	for dir in dir_list:
		#print(f'dir:{dir}')
		if dir not in current_dict:
			boolean = False
			break
		current_dict = current_dict[dir]
		
	# not_exist = False
	# current_base = smali_base_dir
	# for dir in dir_list:
	# 	new_cur = os.path.join(current_base,dir)
	# 	if not os.path.isdir(new_cur):
	# 		not_exist = True
	# 		break
	# 	current_base = new_cur
	# if boolean and not not_exist:
	# 	input(f'target function:{method_sign}的class在路徑上?')
	# if boolean:
	# 	print(f'method_sign:{method_sign},boolean:{boolean}')
	return boolean

if __name__ == '__main__':
    # print(get_registers_usage_in_line('    add-double p15, p1, p15'))
    # print(get_registers_usage_in_line('    iput-object v2, v13, La/b/e;->b:[Ljava/lang/Object;'))
    # print(get_registers_usage_in_line('    invoke-static/range {v4 .. p1}, LSADroid/InlineLogs;->monitorLog2(Ljava/lang/String;Ljava/lang/String;)V'))
    print(get_invoke_range_regs_ver2('    invoke-static/range {v4 .. p1}, LSADroid/InlineLogs;->monitorLog2(Ljava/lang/String;Ljava/lang/String;)V', 10))
    print(get_registers_usage_in_line('    move-exception p1'))
        
    
    # line = '    or-int/lit16 v3, v3, 0x80\n'
    # ins = line.strip().split(' ')[0]
    # b = (any([line.startswith(prefix) for prefix in ['    add', '    sub', '    mul', '    div', '    rem', '    and', \
    #         '    or', '    xor', '    shl', '    shr', '    ushr']]) and not '2addr' in ins and not 'lit16' in ins)
    # c = any([line.startswith(prefix) \
    #     for prefix in ['    return', '    move-result', '    const ', '    const-wide', '    monitor', '    check-', \
    #         '    new-instance', '    throw', '    cmp', '    fill-']]) \
    #     or any([substr in ins for substr in ['/16', '/from16', 'range', 'switch']])\
    #     or (line.startswith('if-') and 'z' in ins)\
    #     or (('put' in ins or 'get' in ins) and not ins.startswith('i'))\
    #     or (any([line.startswith(prefix) for prefix in ['    add', '    sub', '    mul', '    div', '    rem', '    and', \
    #         '    or', '    xor', '    shl', '    shr', '    ushr']]) and not '2addr' in ins and not 'lit16' in ins) 
    # print(b,c)
    # print(is_4bit_instruction(line))