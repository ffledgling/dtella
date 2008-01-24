from distutils.core import setup
import sys

class Error(Exception):
    pass

def get_excludes():
    ex = []
    
    # The GData fetcher may need these, but leave them out for now.
    ex.append("xml")
    ex.append("_ssl")

    # Skip over any bridge components.
    ex.append("dtella.bridge_config")
    ex.append("dtella.bridge")

    return ex


def patch_nsi_template():
    # Generate NSI file from template, replacing name and version
    # with data from local_config.

    import dtella.local_config as local
    import re
    
    dt_name = local.hub_name
    dt_version = local.version
    dt_simplename = None

    # Pull DT_DIR from build_installer.bat
    for line in file("installer/build_installer.bat"):
        m = re.match(r'set DTDIR="(.+)"', line)
        if m:
            dt_simplename = m.group(1)
            break
    if not dt_simplename:
        raise Error("Can't find DTDIR in build_installer.bat")

    wfile = file("installer/dtella.nsi", "w")

    for line in file("installer/dtella.template.nsi"):
        if "PATCH_ME" in line:
            if "PRODUCT_NAME" in line:
                line = line.replace("PATCH_ME", dt_name)
            elif "PRODUCT_VERSION" in line:
                line = line.replace("PATCH_ME", dt_version)
            elif "PRODUCT_SIMPLENAME" in line:
                line = line.replace("PATCH_ME", dt_simplename)
            else:
                raise Error("Unpatchable NSI line: %s" % line)
        wfile.write(line)
    wfile.close()


if sys.platform == 'darwin':
    import py2app
elif sys.platform == 'win32':
    import py2exe
    patch_nsi_template()
else:
    print "Unknown platform: %s" % sys.platform
    sys.exit(-1)

excludes = get_excludes()

setup(
    options={
        "py2exe": {
            "optimize": 2,
            "bundle_files": 1,
            "ascii": True,
            "dll_excludes": ["libeay32.dll"],
            "excludes": excludes,
        },

        # TODO: Find out how to make the mac build process easier.
        "py2app": {
            "optimize": 2,
            "argv_emulation": True,
            "iconfile": "icons/dtella.icns",
            "plist": {'LSBackgroundOnly':True},
            "excludes": excludes,
        }
    },

    app=["dtella.py"],

    zipfile=None,
    windows=[{
        "script": "dtella.py",
        "icon_resources": [(1, "icons/dtella.ico"), (10, "icons/kill.ico")],
    }]
)
