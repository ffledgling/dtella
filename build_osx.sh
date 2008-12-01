# set FILEBASE
eval $(python makevars.py)

BLDIR="installer_osx"
OUTDIR="dist"

rm -r build
rm $BLDIR/template.sparseimage
rm $OUTDIR/$FILEBASE.dmg

python setup.py py2app || exit

hdiutil eject /Volumes/Dtella
hdiutil eject /Volumes/$FILEBASE

hdiutil convert $BLDIR/template.dmg -format UDSP -o $BLDIR/template
hdiutil attach $BLDIR/template.sparseimage

cp -R dist/dtella.app/ /Volumes/Dtella/Dtella.app
cp docs/readme.txt /Volumes/Dtella/
cp docs/changelog.txt /Volumes/Dtella/
cp docs/gpl.txt /Volumes/Dtella/

diskutil rename /Volumes/Dtella/ $FILEBASE
hdiutil eject /Volumes/$FILEBASE

hdiutil convert $BLDIR/template.sparseimage -format UDBZ -o $FILEBASE.dmg

mv $FILEBASE.dmg $OUTDIR

rm $BLDIR/template.sparseimage
