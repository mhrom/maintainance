@echo off
::Ask
echo Your Source Path:
set INPUT1=
set /P INPUT1=Type input: %=%

echo Your Destination Path:
set INPUT2=
set /P INPUT2=Type input: %=%

xcopy %INPUT1% %INPUT2% /y /s
