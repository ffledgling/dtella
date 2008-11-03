@echo off
set BLDIR="installer_win"
set DTDIR="dtella-purdue-SVN"
set ARC="C:\Program Files\7-Zip\7z.exe"
set NSIS="C:\Program Files\NSIS\makensis.exe"
set NSIS64="C:\Program Files (x86)\NSIS\makensisw.exe"
set OUTDIR="dist"


REM ----- DEPENDENCY CHECK ------

echo Now Checking for Build Utilities...
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


REM ------- SOURCE CODE ---------
echo Collecting source code...

rmdir /s /q %BLDIR%/%DTDIR%
del %BLDIR%/%DTDIR%.tar
del %BLDIR%/%DTDIR%.tar.bz2

mkdir %BLDIR%/%DTDIR%
mkdir %BLDIR%/%DTDIR%/dtella
mkdir %BLDIR%/%DTDIR%/dtella/client
mkdir %BLDIR%/%DTDIR%/dtella/common
mkdir %BLDIR%/%DTDIR%/dtella/modules
mkdir %BLDIR%/%DTDIR%/docs

copy dtella.py                %BLDIR%\%DTDIR%
copy dtella\__init__.py       %BLDIR%\%DTDIR%\dtella
copy dtella\local_config.py   %BLDIR%\%DTDIR%\dtella
copy dtella\client\*.py       %BLDIR%\%DTDIR%\dtella\client
copy dtella\common\*.py       %BLDIR%\%DTDIR%\dtella\common
copy dtella\modules\*.py      %BLDIR%\%DTDIR%\dtella\modules
copy docs\readme.txt          %BLDIR%\%DTDIR%\docs
copy docs\changelog.txt       %BLDIR%\%DTDIR%\docs
copy docs\requirements.txt    %BLDIR%\%DTDIR%\docs
copy docs\gpl.txt             %BLDIR%\%DTDIR%\docs

pushd %BLDIR%
%ARC% a -ttar %DTDIR%.tar %DTDIR%
%ARC% a -tbzip2 %DTDIR%.tar.bz2 %DTDIR%.tar

del %DTDIR%.tar
rmdir /s /q %DTDIR%
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

move %BLDIR%\%DTDIR%.exe %OUTDIR%
move %BLDIR%\%DTDIR%.tar.* %OUTDIR%


del %BLDIR%\msvcr71.dll
del %BLDIR%\readme.txt
del %BLDIR%\changelog.txt
del %BLDIR%\dtella.exe
del %BLDIR%\dtella.nsi
