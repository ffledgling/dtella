if [ -z $1 ]
then
  FILE_BASE="dtella-purdue-SVN"
else
  FILE_BASE="dtella-$1"
fi

BLDIR="installer_osx"
OUTDIR="dist"

rm -r build
rm $BLDIR/template.sparseimage
rm $OUTDIR/$FILE_BASE.dmg

python setup.py py2app || exit

hdiutil eject /Volumes/Dtella
hdiutil eject /Volumes/$FILE_BASE

hdiutil convert $BLDIR/template.dmg -format UDSP -o $BLDIR/template
hdiutil attach $BLDIR/template.sparseimage

cp -R dist/dtella.app/ /Volumes/Dtella/Dtella.app
cp docs/readme.txt /Volumes/Dtella/
cp docs/changelog.txt /Volumes/Dtella/
cp docs/gpl.txt /Volumes/Dtella/

diskutil rename /Volumes/Dtella/ $FILE_BASE
hdiutil eject /Volumes/$FILE_BASE

hdiutil convert $BLDIR/template.sparseimage -format UDBZ -o $FILE_BASE.dmg

mv $FILE_BASE.dmg $OUTDIR

rm $BLDIR/template.sparseimage