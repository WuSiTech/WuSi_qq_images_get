@echo off
chcp 65001 >nul
rem 带命令行窗口启动，便于看到报错信息
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "qq_group_images.py"
) else (
    python "qq_group_images.py"
)
if errorlevel 1 pause
