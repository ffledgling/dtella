from distutils.core import setup
import sys

if sys.platform == 'darwin':
    import py2app
else:
    import py2exe

setup(
    options={
        "py2exe":{
            "optimize":2,
            "dll_excludes": ["libeay32.dll"]
        },
        
        "py2app":{
            "argv_emulation":True,
            "iconfile": "icons/dtella.icns",
            "plist":{'LSBackgroundOnly':True}
        }
    },

    app=["dtella.py"],

    zipfile=None,
    windows=[{
        "script": "dtella.py",
        "icon_resources": [(1, "icons/dtella.ico"), (10, "icons/kill.ico")],
    }]

    #console=[{
    #    "script": "dtella.py",
    #    "icon_resources": [(1, "dtella.ico")]
    #}]
)
