from distutils.core import setup
import py2exe
setup(
    options={"py2exe":{"optimize":2}},
    zipfile=None,

    windows=[{
        "script": "dtella.py",
        "icon_resources": [(1, "dtella.ico")]
    }]

    #console=[{
    #    "script": "dtella.py",
    #    "icon_resources": [(1, "dtella.ico")]
    #}]
)

