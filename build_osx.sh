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

mkdir dist
cp docs/readme.txt dist/
cp docs/changelog.txt dist/
cp docs/gpl.txt dist/

python setup.py py2app || exit

hdiutil convert installer_osx/template.dmg -format UDSP -o installer_osx/template
hdiutil mount installer_osx/template.sparseimage

cp -R dist/dtella.app/ /Volumes/Dtella/Dtella.app
cp dist/readme.txt /Volumes/Dtella/
cp dist/changelog.txt /Volumes/Dtella/
cp dist/gpl.txt /Volumes/Dtella/

diskutil rename /Volumes/Dtella/ $FILE_BASE
hdiutil eject /Volumes/$FILE_BASE

hdiutil convert installer_osx/template.sparseimage -format UDBZ -o $FILE_BASE.dmg

rm installer_osx/template.sparseimage