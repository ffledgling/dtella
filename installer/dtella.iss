;dtella.iss - Windows installer script for Dtella
;
;Copyright (C) 2007  Dtella Labs (www.dtella.org)
;Copyright (C) 2007  Jacob Feisley, Paul Marks
;
;This program is free software; you can redistribute it and/or
;modify it under the terms of the GNU General Public License
;as published by the Free Software Foundation; either version 2
;of the License, or (at your option) any later version.
;
;This program is distributed in the hope that it will be useful,
;but WITHOUT ANY WARRANTY; without even the implied warranty of
;MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;GNU General Public License for more details.
;
;You should have received a copy of the GNU General Public License
;along with this program; if not, write to the Free Software
;Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


[Setup]
AppPublisher=Dtella Labs
AppPublisherURL=http://www.dtella.org/
AppVersion=0.8.0

AppName=Dtella
AppVerName=Dtella Beta
DefaultDirName={pf}\Dtella
DefaultGroupName=Dtella Labs
UninstallDisplayIcon={app}\dtella.exe

[Types]
Name: "standard"; Description: "Standard installation"
Name: "complete"; Description: "Complete installation"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "program"; Description: "Dtella"; Types: standard complete custom; Flags: fixed
Name: "source"; Description: "Source Code"; Types: complete;

[Files]
Source: "dtella.exe"; DestDir: "{app}"; Components: program
Source: "readme.txt"; DestDir: "{app}"; Components: program
Source: "msvcr71.dll"; DestDir: "{app}"; Components: program

Source: "source.zip"; DestDir: "{app}"; Components: "source"


[Icons]
Name: "{group}\Dtella"; Filename: "{app}\dtella.exe"
Name: "{group}\Kill Dtella"; Filename: "{app}\dtella.exe"; Parameters: "--terminate"


[UninstallRun]
Filename: "{app}\dtella.exe"; Parameters: "--terminate"

[Run]
Filename: "{app}\dtella.exe"; Description: "Run Dtella"; Flags: postinstall nowait skipifsilent
Filename: "{app}\readme.txt"; Description: "View the README file"; Flags: postinstall shellexec skipifsilent






[Code]
function NextButtonClick(CurPageID: Integer): Boolean;
var
  ResultCode: Integer;
begin
  case CurPageID of
    wpReady:
      begin
        begin
          ExtractTemporaryFile('dtella.exe');
          if not Exec(ExpandConstant('{tmp}\dtella.exe'), '--terminate', '', SW_SHOWNORMAL, ewWaitUntilTerminated, ResultCode) then
            MsgBox('NextButtonClick:' #13#13 'The file could not be executed. ' + SysErrorMessage(ResultCode) + '.', mbError, MB_OK);
        end;
        BringToFrontAndRestore();
      end;
  end;

  Result := True;
end;




