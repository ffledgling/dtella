@ECHO OFF
REM Exclude SSL and XML because they're big and not used
REM --ascii prevents a million other encodings from getting added
REM --bundle 1 bundles the DLLs into the EXE.

dist\dtella.exe --terminate

REM delete old directores
rmdir /s /q build
rmdir /s /q dist

c:\python25\python setup.py py2exe -O2 --ascii --exclude xml,_ssl --bundle 1

REM Dtella doesn't use os.popen, so...
del dist\w9xpopen.exe

pause
