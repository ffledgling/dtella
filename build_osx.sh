if [ -z $1 ]
then
  FILE_BASE="dtella-purdue-SVN"
else
  FILE_BASE="dtella-$1"
fi

rm -r dist
rm $FILE_BASE.dmg

mkdir dist
cp docs/readme.txt dist/
cp docs/changelog.txt dist/
cp docs/gpl.txt dist/

python setup.py py2app
hdiutil create -srcfolder dist -volname $FILE_BASE $FILE_BASE.dmg
