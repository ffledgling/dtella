#!/usr/bin/env python
import sys
import dtella.local_config as local

if sys.platform.startswith("win"):
    export = "set"
else:
    export = "export"

print '%s FILEBASE="%s"' % (export, local.build_prefix + local.version)
