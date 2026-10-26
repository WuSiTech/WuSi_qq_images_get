@echo off
rem 静默启动（不显示黑色命令行窗口）
cd /d "%~dp0"
where pyw >nul 2>nul
if %errorlevel%==0 (
    start "" pyw -3 "qq_group_images.py"
) else (
    where pythonw >nul 2>nul
    if %errorlevel%==0 (
        start "" pythonw "qq_group_images.py"
    ) else (
        start "" py -3 "qq_group_images.py"
    )
)
