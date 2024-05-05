import os
import json

# evasions文件夹路径
evasions_dir = "evasions"

# 用于存储所有evasion数据的字典
all_evasions = {}

# 遍历evasions文件夹下的所有app子文件夹
for app_dir in os.listdir(evasions_dir):
    app_path = os.path.join(evasions_dir, app_dir)
    
    # 检查是否为文件夹
    if os.path.isdir(app_path):
        evasion_file = os.path.join(app_path, "evasion.json")
        
        # 检查evasion.json文件是否存在且不为空
        if os.path.isfile(evasion_file) and os.path.getsize(evasion_file) > 0:
            # 读取evasion.json文件内容
            with open(evasion_file, "r") as f:
                try:
                    evasion_data = json.load(f)
                except json.JSONDecodeError:
                    print(f"Invalid JSON data in {evasion_file}. Skipping.")
                    continue
            
            # 将evasion数据添加到all_evasions字典中，使用app子文件夹名称作为key
            all_evasions[app_dir] = evasion_data

# 将all_evasions字典写入all_evasions.json文件
with open("all_evasions.json", "w") as f:
    json.dump(all_evasions, f, indent=4)

print("合并完成！")