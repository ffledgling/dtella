@echo off
set DTDIR="dtella-purdue-SVN"
set ARC="C:\Program Files\7-Zip\7z.exe"
set NSIS="C:\Program Files\NSIS\makensis.exe"
set NSIS64="C:\Program Files (x86)\NSIS\makensisw.exe"
set OUTDIR="Output"


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

rmdir /s /q %DTDIR%
del %DTDIR%.tar
del %DTDIR%.tar.bz2

mkdir %DTDIR%
mkdir %DTDIR%/dtella
mkdir %DTDIR%/dtella/client
mkdir %DTDIR%/dtella/common
mkdir %DTDIR%/dtella/modules
mkdir %DTDIR%/docs

copy ..\dtella.py                %DTDIR%
copy ..\dtella\__init__.py       %DTDIR%\dtella
copy ..\dtella\local_config.py   %DTDIR%\dtella
copy ..\dtella\client\*          %DTDIR%\dtella\client
copy ..\dtella\common\*          %DTDIR%\dtella\common
copy ..\dtella\modules\*         %DTDIR%\dtella\modules
copy ..\docs\readme.txt          %DTDIR%\docs
copy ..\docs\changelog.txt       %DTDIR%\docs
copy ..\docs\requirements.txt    %DTDIR%\docs
copy ..\docs\gpl.txt             %DTDIR%\docs

%ARC% a -ttar %DTDIR%.tar %DTDIR%
%ARC% a -tbzip2 %DTDIR%.tar.bz2 %DTDIR%.tar

del %DTDIR%.tar
rmdir /s /q %DTDIR%


REM ------- EXE -------------
echo Building Windows binary files...

pushd ..
call build_py2exe
popd

REM ------- DOCS ------------

copy ..\docs\readme.txt .
copy ..\docs\changelog.txt .


REM ------- INSTALLER -------
echo Building the installer...

IF EXIST %NSIS% (%NSIS% dtella.nsi) ELSE (%NSIS64% dtella.nsi)

echo The build process is now complete!
pause


REM -----CLEAN UP OUTPUT------

mkdir Output

move %DTDIR%.exe %OUTDIR%
move %DTDIR%.tar.* %OUTDIR%


del msvcr71.dll
del readme.txt
del changelog.txt
del dtella.exe
del dtella.nsi
