set DTDIR="dtella-purdue-0.9"
set ARC="C:\Program Files\7-Zip\7z.exe"
set NSIS="C:\Program Files\NSIS\makensisw.exe"


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


REM ------- INSTALLER -------

%NSIS% dtella.nsi

pause