; Dtella - NSIS Installer Script
; Copyright (C) 2007  Paul Marks
; Copyright (C) 2007  Jacob Feisley
; http://www.dtella.org/
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
!define PRODUCT_VERSION "0.9"
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
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

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
SectionEnd

Section "!Dtella (Required)" Section_EXE
  SectionIn 1 RO
  SetOutPath "$INSTDIR"
  File "dtella.exe"
  File "msvcr71.dll"
  File "readme.txt"
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Dtella (Run in Background).lnk" "$INSTDIR\dtella.exe"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Kill Dtella.lnk" "$INSTDIR\dtella.exe" "--terminate"
SectionEnd

Section /o "Source Code" Section_SOURCE
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
  !insertmacro MUI_DESCRIPTION_TEXT ${Section_EXE} "The main Dtella program."
  !insertmacro MUI_DESCRIPTION_TEXT ${Section_Source} "If you don't know what this is for, then you don't need it."
!insertmacro MUI_FUNCTION_DESCRIPTION_END


; Uninstaller Stuff

Function un.onInit
  MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove $(^Name) and all of its components?" IDYES +2
  Abort
FunctionEnd

Section Uninstall
  SetShellVarContext all
  
  ExecWait '"$INSTDIR\dtella.exe" --terminate'

  Delete "$INSTDIR\uninst.exe"
  Delete "$INSTDIR\readme.txt"
  Delete "$INSTDIR\msvcr71.dll"
  Delete "$INSTDIR\dtella.exe"
  Delete "$INSTDIR\dtella-purdue-*.tar.bz2"
  RMDir "$INSTDIR"

  Delete "$PROFILE\.dtella\dtella.state"
  RmDir "$PROFILE\.dtella"
  
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Dtella (Run in Background).lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Kill Dtella.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
  
  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
SectionEnd