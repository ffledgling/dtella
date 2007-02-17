set DTDIR="dtella-purdue-SVN"
set ARC="C:\Program Files\7-Zip\7z.exe"
set NSIS="C:\Program Files\NSIS\makensisw.exe"
set OUTDIR="Output"


REM ------- SOURCE CODE ---------

rmdir /s /q %DTDIR%
del %DTDIR%.tar
del %DTDIR%.tar.bz2

mkdir %DTDIR%

copy ..\dtella.py                %DTDIR%
copy ..\dtella_bridgeclient.py   %DTDIR%
copy ..\dtella_core.py           %DTDIR%
copy ..\dtella_crypto.py         %DTDIR%
copy ..\dtella_dc.py             %DTDIR%
copy ..\dtella_dnslookup.py      %DTDIR%
copy ..\dtella_fixtwistedtime.py %DTDIR%
copy ..\dtella_local.py          %DTDIR%
copy ..\dtella_state.py          %DTDIR%
copy ..\dtella_util.py           %DTDIR%
copy ..\docs\readme.txt          %DTDIR%
copy ..\docs\changelog.txt       %DTDIR%
copy ..\docs\requirements.txt    %DTDIR%
copy ..\docs\gpl.txt             %DTDIR%

%ARC% a -ttar %DTDIR%.tar %DTDIR%
%ARC% a -tbzip2 %DTDIR%.tar.bz2 %DTDIR%.tar

del %DTDIR%.tar
rmdir /s /q %DTDIR%


REM ------- EXE -------------

pushd ..
call build_py2exe
popd

REM ------- DOCS ------------

copy ..\docs\readme.txt .
copy ..\docs\changelog.txt .


REM ------- INSTALLER -------

%NSIS% dtella.nsi

pause


REM -----CLEAN UP OUTPUT------

mkdir Output

move %DTDIR%.exe %OUTDIR%
move %DTDIR%.tar.* %OUTDIR%


del msvcr71.dll
del readme.txt
del changelog.txt
del dtella.exe