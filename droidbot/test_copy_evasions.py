import os
import shutil

# dcfg文件夹路径
dcfg_dir = "dcfg"

# evasions文件夹路径
evasions_dir = "evasions"

# 遍历dcfg文件夹下的所有app子文件夹
for app_dir in os.listdir(dcfg_dir):
    app_path = os.path.join(dcfg_dir, app_dir)
    
    # 检查是否为文件夹
    if os.path.isdir(app_path):
        evasion_file = os.path.join(app_path, "evasion.json")
        
        # 检查evasion.json文件是否存在
        if os.path.isfile(evasion_file):
            # 在evasions文件夹中创建相应的app子文件夹
            new_app_dir = os.path.join(evasions_dir, app_dir)
            os.makedirs(new_app_dir, exist_ok=True)
            
            # 复制evasion.json文件到新的app子文件夹中
            new_evasion_file = os.path.join(new_app_dir, "evasion.json")
            shutil.copy2(evasion_file, new_evasion_file)