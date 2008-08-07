if [ -z $1 ]
then
  FILE_BASE="dtella-purdue-SVN"
else
  FILE_BASE="dtella-$1"
fi

rm -r build
rm -r dist
rm installer_osx/template.sparseimage
rm $FILE_BASE.dmg

python setup.py py2app || exit

hdiutil eject /Volumes/Dtella
hdiutil eject /Volumes/$FILE_BASE

hdiutil convert installer_osx/template.dmg -format UDSP -o installer_osx/template
hdiutil attach installer_osx/template.sparseimage

cp -R dist/dtella.app/ /Volumes/Dtella/Dtella.app
cp docs/readme.txt /Volumes/Dtella/
cp docs/changelog.txt /Volumes/Dtella/
cp docs/gpl.txt /Volumes/Dtella/

diskutil rename /Volumes/Dtella/ $FILE_BASE
hdiutil eject /Volumes/$FILE_BASE

hdiutil convert installer_osx/template.sparseimage -format UDBZ -o $FILE_BASE.dmg

rm installer_osx/template.sparseimage