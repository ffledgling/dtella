; Dtella - NSIS Installer Script
; Copyright (C) 2007  Dtella Labs (http://www.dtella.org/)
; Copyright (C) 2007  Paul Marks (http://www.pmarks.net/)
; Copyright (C) 2007  Jacob Feisley  (http://www.feisley.com/)
;
; This program is free software; you can redistribute it and/or
; modify it under the terms of the GNU General Public License
; as published by the Free Software Foundation; either version 2
; of the License, or (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program; if not, write to the Free Software
; Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.



!define PRODUCT_NAME "Dtella@Purdue"
!define PRODUCT_VERSION "SVN"
!define PRODUCT_PUBLISHER "Dtella Labs"
!define PRODUCT_WEB_SITE "http://www.dtella.org/"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\dtella.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

SetCompressor lzma

; MUI 1.67 compatible ------
!include "MUI.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "..\icons\labs.ico"
!define MUI_UNICON "..\icons\labs.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP ".\resources\welcome.bmp"

!define MUI_COMPONENTSPAGE_SMALLDESC
!define MUI_FINISHPAGE_RUN "$INSTDIR\dtella.exe"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\readme.txt"

; Installer Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_COMPONENTS
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"

; Reserve files
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

; MUI end ------

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "dtella-purdue-${PRODUCT_VERSION}.exe"
InstallDir "$PROGRAMFILES\Dtella@Purdue"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show

Section -Pre
  SetShellVarContext all
  ExecWait '"$INSTDIR\dtella.exe" --terminate'


  ;This will prompt for the uninstallation of DCgate
  StrCpy $R0 "{88D0F3EF-D185-4B94-9667-05F042C63B08}"
  Call UninstallDCgate

SectionEnd


Section "!Dtella (Required)" INST_DTELLA
  SectionIn 1 RO
  SetOutPath "$INSTDIR"
  File "dtella.exe"
  File "msvcr71.dll"
  File "readme.txt"
  File "changelog.txt"
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Dtella (Run in Background).lnk" "$INSTDIR\dtella.exe"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Kill Dtella.lnk" "$INSTDIR\dtella.exe" "--terminate" "$INSTDIR\dtella.exe" 1
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Readme.lnk" "$INSTDIR\readme.txt"
  CreateShortcut "$SMPROGRAMS\${PRODUCT_NAME}\Changelog.lnk" "$INSTDIR\changelog.txt"
SectionEnd

Section /o "Source Code" INST_SOURCE
  SetOutPath "$INSTDIR"
  File "dtella-purdue-${PRODUCT_VERSION}.tar.bz2"
SectionEnd

Section -AdditionalIcons
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" "$INSTDIR\uninst.exe"
SectionEnd

Section -Post
  WriteUninstaller "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\dtella.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\dtella.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
SectionEnd

; Section Descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${INST_DTELLA} "The main Dtella program."
  !insertmacro MUI_DESCRIPTION_TEXT ${INST_SOURCE} "If you don't know what this is for, then you don't need it."
!insertmacro MUI_FUNCTION_DESCRIPTION_END


; Uninstaller Stuff

Section -un.Pre
  SetShellVarContext all
  ExecWait '"$INSTDIR\dtella.exe" --terminate'
SectionEnd

Section "un.Dtella" UNINST_DTELLA
  SectionIn 1 RO
  Delete "$INSTDIR\uninst.exe"
  Delete "$INSTDIR\readme.txt"
  Delete "$INSTDIR\changelog.txt"
  Delete "$INSTDIR\msvcr71.dll"
  Delete "$INSTDIR\dtella.exe"
  Delete "$INSTDIR\dtella-purdue-*.tar.bz2"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Dtella (Run in Background).lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Kill Dtella.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Readme.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Changelog.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
  
  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
SectionEnd

Section "un.Dtella Settings File" UNINST_SETTINGS
  Delete "$PROFILE\.dtella\dtella.state"
  RmDir "$PROFILE\.dtella"
SectionEnd


; Uninstall Section Descriptions
!insertmacro MUI_UNFUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${UNINST_DTELLA} "Uninstalls the main Dtella program."
  !insertmacro MUI_DESCRIPTION_TEXT ${UNINST_SETTINGS} "This file contains Dtella's UDP port, along with other temporary data."
!insertmacro MUI_UNFUNCTION_DESCRIPTION_END



;This will prompt for the uninstallation of DCgate
Function UninstallDCgate
  push $R1
  ReadRegStr $R1 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\$R0" "UninstallString"
  StrCmp $R1 "" UninstallMSI_nomsi
    MessageBox MB_YESNO|MB_ICONQUESTION "We have detected a copy of DCgate on your computer.$\nDCgate will no longer be useful, so we recommend that you remove it.$\n$\nDo you want to remove DCgate?" IDNO UninstallMSI_nomsi IDYES UninstallMSI_yesmsi
      Abort
UninstallMSI_yesmsi:
    ExecWait '"taskkill.exe" /f /im dcgate.exe'
    ExecWait '"msiexec.exe" /x $R0'
    MessageBox MB_OK|MB_ICONINFORMATION "Click OK to continue upgrading to Dtella"
UninstallMSI_nomsi:
  pop $R1
FunctionEnd
