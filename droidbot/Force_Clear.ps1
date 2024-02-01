# 指定要刪除的文件或目錄路徑
$pathToDelete = "C:\Users\user\Desktop\SADroid\droidbot\output"

# 終止使用該路徑中文件的進程
# Get-Process | ForEach-Object {
#     try {
#         $_.Modules | Where-Object { $_.FileName -like $pathToDelete } | Stop-Process -Force
#     } catch {
#         # 忽略無法訪問進程模塊的錯誤
#     }
# }

# 強制刪除文件或文件夾
Remove-Item -Path $pathToDelete -Recurse -Force
