#!/usr/bin/env python
# Tests for dtella/bridge/inspircd.py

import fix_path
import unittest
from dtella.common.ipv4 import Ad
from dtella.bridge.inspircd import HalfModeCloak
from dtella.bridge.bridge_server import BadHostnameError


class InspircdTestCase(unittest.TestCase):
    def testHalfModeCloak(self):
        cloak = HalfModeCloak("pre-", "s33kr1t")
        self.assertEqual(
            cloak.maskHostname("c-99-100-123-231.hsd1.ca.comcast.net"),
            "pre-pkjbqg.ca.comcast.net")
        self.assertEqual(
            cloak.maskHostname("foo.bar.dtella.org"),
            "pre-hsfn1d.bar.dtella.org")
        self.assertEqual(
            cloak.maskHostname("hawk-d-999.resnet.purdue.edu"),
            "pre-doft6g.resnet.purdue.edu")
        self.assertEqual(
            cloak.maskIPv4(Ad().setTextIP("0.0.0.0")),
            "pre-j88.3ss.0.0.IP")
        self.assertEqual(
            cloak.maskIPv4(Ad().setTextIP("12.34.56.78")),
            "pre-6l1.prh.34.12.IP")
        self.assertEqual(
            cloak.maskHostname("localhost.localdomain"),
            "pre-alqii9.localdomain")

        # Too short/long hostnames should raise an error.
        self.assertRaises(BadHostnameError, cloak.maskHostname, None)
        self.assertRaises(BadHostnameError, cloak.maskHostname, "")
        self.assertRaises(BadHostnameError, cloak.maskHostname, "z" * 51)

    def testLastTwoDomainParts(self):
        cloak = HalfModeCloak("prefix", "key")
        self.assertEqual(cloak.lastTwoDomainParts("svn.inspircd.org"),
                         ".inspircd.org")
        self.assertEqual(cloak.lastTwoDomainParts("brainbox.winbot.co.uk"),
                         ".winbot.co.uk")
        self.assertEqual(cloak.lastTwoDomainParts("localhost.localdomain"),
                         ".localdomain")
        self.assertEqual(cloak.lastTwoDomainParts("a.b.c.d.e.f.g"), ".e.f.g")
        self.assertEqual(cloak.lastTwoDomainParts("zzz"), "")
        self.assertEqual(cloak.lastTwoDomainParts(""), "")


if __name__ == "__main__":
    unittest.main()
