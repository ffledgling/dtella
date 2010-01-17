@echo off
set BLDIR="installer_win"
set ARC="C:\Program Files\7-Zip\7z.exe"
set NSIS="C:\Program Files\NSIS\makensis.exe"
set NSIS64="C:\Program Files (x86)\NSIS\makensisw.exe"
set PYTHON="C:\python25\python.exe"
set OUTDIR="dist"

REM ----- DEPENDENCY CHECK ------
echo Now Checking for Build Utilities...

IF EXIST %PYTHON% (echo Found Python...) ELSE (
echo ERROR: Python 2.5 Not Found.
pause
EXIT
)

IF EXIST %ARC% (echo Found 7-Zip Archiver...) ELSE (
echo ERROR: 7-Zip Archiver Not Found.
pause
EXIT
)

IF EXIST %NSIS% (echo Found NSIS compiler...) ELSE (
IF EXIST %NSIS64% (echo Found NSIS compiler...) ELSE (
echo ERROR: NSIS Compiler Not Found.
pause
EXIT
) )
echo All Dependencies Found, continuing...

REM ----- SET FILEBASE -----
%PYTHON% makevars.py > makevars.bat
call makevars.bat
del makevars.bat
IF ()==(%FILEBASE%) (
echo ERROR: Could not generate FILEBASE.
pause
EXIT
)

REM ------- SOURCE CODE ---------
echo Collecting source code...

rmdir /s /q %BLDIR%/%FILEBASE%
del %BLDIR%/%FILEBASE%.tar
del %BLDIR%/%FILEBASE%.tar.bz2

mkdir %BLDIR%/%FILEBASE%
mkdir %BLDIR%/%FILEBASE%/dtella
mkdir %BLDIR%/%FILEBASE%/dtella/client
mkdir %BLDIR%/%FILEBASE%/dtella/common
mkdir %BLDIR%/%FILEBASE%/dtella/modules
mkdir %BLDIR%/%FILEBASE%/docs

copy dtella.py                %BLDIR%\%FILEBASE%
copy dtella\__init__.py       %BLDIR%\%FILEBASE%\dtella
copy dtella\local_config.py   %BLDIR%\%FILEBASE%\dtella
copy dtella\client\*.py       %BLDIR%\%FILEBASE%\dtella\client
copy dtella\common\*.py       %BLDIR%\%FILEBASE%\dtella\common
copy dtella\modules\*.py      %BLDIR%\%FILEBASE%\dtella\modules
copy docs\readme.txt          %BLDIR%\%FILEBASE%\docs
copy docs\changelog.txt       %BLDIR%\%FILEBASE%\docs
copy docs\requirements.txt    %BLDIR%\%FILEBASE%\docs
copy docs\gpl.txt             %BLDIR%\%FILEBASE%\docs

pushd %BLDIR%
%ARC% a -ttar %FILEBASE%.tar %FILEBASE%
%ARC% a -tbzip2 %FILEBASE%.tar.bz2 %FILEBASE%.tar

del %FILEBASE%.tar
rmdir /s /q %FILEBASE%
popd

REM ------- EXE -------------
echo Building Windows binary files...

call build_py2exe
copy dist\dtella.exe %BLDIR%
copy dist\msvcr71.dll %BLDIR%

REM ------- DOCS ------------

copy docs\readme.txt %BLDIR%
copy docs\changelog.txt %BLDIR%


REM ------- INSTALLER -------
echo Building the installer...
pushd %BLDIR%

IF EXIST %NSIS% (%NSIS% dtella.nsi) ELSE (%NSIS64% dtella.nsi)

echo The build process is now complete!
popd

pause



REM -----CLEAN UP OUTPUT------

mkdir %OUTDIR%

move %BLDIR%\%FILEBASE%.exe %OUTDIR%
move %BLDIR%\%FILEBASE%.tar.* %OUTDIR%


del %BLDIR%\msvcr71.dll
del %BLDIR%\readme.txt
del %BLDIR%\changelog.txt
del %BLDIR%\dtella.exe
del %BLDIR%\dtella.nsi
