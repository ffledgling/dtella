dist\dtella.exe --terminate

REM delete old directores
rmdir /s /q build
rmdir /s /q dist

c:\python25\python setup.py py2exe

copy dist\dtella.exe installer
copy dist\msvcr71.dll installer

pause
