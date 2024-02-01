param (
    [string]$apkFolder,
    [string]$outputFolder,
    [int]$eventCount = 10,
    [int]$timeoutSeconds = 300 # 例如，設置為 5 分鐘
)

# 獲取 APK 文件並隨機排序
$apkFiles = Get-ChildItem -Path $apkFolder -Filter "repacked_*.apk" -Recurse | Get-Random -Count (Get-ChildItem -Path $apkFolder -Filter "repacked_*.apk" -Recurse).Count

foreach ($file in $apkFiles) {
    $apkPath = $file.FullName
    $apkName = $file.Name
    Write-Host "Found APK: $apkPath"

    $deviceList = adb devices | Select-String -Pattern 'device$' | ForEach-Object { $_ -replace '\tdevice', '' }
    Write-Host "Current devices: $deviceList"

    foreach ($device in $deviceList) {
        Write-Host "Handling device: $device"
        $outputDir = Join-Path -Path $outputFolder -ChildPath "$apkName-$device"
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir | Out-Null
        }
        Write-Host "Output to: $outputDir"

        $logFileOut = Join-Path -Path $outputDir -ChildPath "droidbot_output_log.txt"
        $logFileErr = Join-Path -Path $outputDir -ChildPath "droidbot_error_log.txt"
        Write-Host "Execution: $logFileOut, $logFileErr"

        $droidBotProcess = Start-Process python -ArgumentList ".\start.py -keep_env -accessibility_auto -grant_perm -random -a `"$apkPath`" -o `"$outputDir`" -count $eventCount -d $device -ignore_ad -use_method_profiling full" -PassThru -RedirectStandardOutput $logFileOut -RedirectStandardError $logFileErr -NoNewWindow

        # 設定計時器等待進程結束或超時
        $startTime = Get-Date
        while ($true) {
            if ((Get-Date) - $startTime -gt [TimeSpan]::FromSeconds($timeoutSeconds)) {
                Write-Host "Time limit exceeded for APK: $apkPath"
                $droidBotProcess | Stop-Process
                break
            }
            if ($droidBotProcess.HasExited) {
                break
            }
            Start-Sleep -Seconds 5
        }

        # 卸載 APK
        adb -s $device uninstall $packageName # 這裡的 $packageName 需要替換成 APK 的包名，您可能需要進行額外的處理來從 APK 獲取包名
    }
}
