"""
Dtella - py2exe setup script
Copyright (C) 2007-2008  Dtella Labs (http://dtella.org/)
Copyright (C) 2007-2008  Paul Marks (http://pmarks.net/)
Copyright (C) 2007-2008  Jacob Feisley (http://feisley.com/)

$Id$

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

from distutils.core import setup
import sys
import dtella.local_config as local

class Error(Exception):
    pass

def get_excludes():
    ex = []

    # Ignore XML and SSL, unless the puller needs them.
    def check_attr(o, a):
        try:
            return getattr(o, a)
        except AttributeError:
            return False

    if not check_attr(local.dconfig_puller, 'needs_xml'):
        ex.append("xml")

    if not check_attr(local.dconfig_puller, 'needs_ssl'):
        ex.append("_ssl")

    # No client should need this
    ex.append("OpenSSL")

    # Skip over any bridge components.
    ex.append("dtella.bridge_config")
    ex.append("dtella.bridge")

    return ex


def patch_nsi_template():
    # Generate NSI file from template, replacing name and version
    # with data from local_config.

    dt_name = local.hub_name
    dt_version = local.version
    dt_simplename = local.build_prefix + local.version

    wfile = file("installer_win/dtella.nsi", "w")

    for line in file("installer_win/dtella.template.nsi"):
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
    name = 'Dtella',
    version = local.version,
    description = 'Dtella Client',
    author = 'Dtella Labs',
    url = 'http://dtella.org',
    options = {
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

    app = ["dtella.py"],

    zipfile = None,
    windows = [{
        "script": "dtella.py",
        "icon_resources": [(1, "icons/dtella.ico"), (10, "icons/kill.ico")],
    }]
)
