#!/usr/bin/env python
# Tests for dtella/common/ipv4.py

import fix_path
import unittest
from dtella.common.ipv4 import CidrNumToMask
from dtella.common.ipv4 import CidrStringToIPMask
from dtella.common.ipv4 import IsSubsetOf
from dtella.common.ipv4 import MaskToCidrNum
from dtella.common.ipv4 import SubnetMatcher


class IPv4TestCase(unittest.TestCase):

    def testCidrNumToMask(self):
        self.assertRaises(ValueError, CidrNumToMask, -1)
        self.assertEqual(CidrNumToMask(0), 0)
        self.assertEqual(CidrNumToMask(16), (~0) << 16)
        self.assertEqual(CidrNumToMask(24), (~0) << 8)
        self.assertEqual(CidrNumToMask(32), ~0)
        self.assertRaises(ValueError, CidrNumToMask, 33)

    def testMaskToCidrNum(self):
        self.assertEqual(MaskToCidrNum(0), 0)
        self.assertEqual(MaskToCidrNum(~0 << 8), 24)
        self.assertEqual(MaskToCidrNum(~0 << 1), 31)
        self.assertEqual(MaskToCidrNum(~0), 32)
        self.assertRaises(ValueError, MaskToCidrNum, 12345)

    def testCidrStringToIPMask(self):
        self.assertEqual(CidrStringToIPMask("1.2.3.4/5"),
                         (0x01020304, ~0<<(32-5)))
        self.assertEqual(CidrStringToIPMask("1.2.3.4"), (0x01020304, ~0))
        self.assertRaises(ValueError, CidrStringToIPMask, "1.2.3.4//5")

    def testIsSubsetOf(self):
        C = CidrStringToIPMask
        self.assertTrue(IsSubsetOf(C("132.3.12.34"), C("132.3.0.0/0")))
        self.assertTrue(IsSubsetOf(C("132.3.12.34"), C("132.3.0.0/16")))
        self.assertTrue(IsSubsetOf(C("0.0.0.0/0"), C("0.0.0.0/0")))
        self.assertTrue(IsSubsetOf(C("0.0.0.0/1"), C("0.0.0.0/0")))
        self.assertFalse(IsSubsetOf(C("0.0.0.0/0"), C("0.0.0.0/1")))
        self.assertFalse(IsSubsetOf(C("192.168.0.255"), C("192.168.1.0/24")))
        self.assertTrue(IsSubsetOf(C("192.168.1.0"), C("192.168.1.0/24")))
        self.assertTrue(IsSubsetOf(C("192.168.1.255"), C("192.168.1.0/24")))
        self.assertFalse(IsSubsetOf(C("192.168.2.0"), C("192.168.1.0/24")))
        self.assertTrue(IsSubsetOf(C("192.168.1.0/24"), C("192.168.0.0/16")))
        self.assertFalse(IsSubsetOf(C("10.0.0.0/24"), C("192.168.0.0/16")))

    def testSubnetMatcher(self):
        C = CidrStringToIPMask
        matcher = SubnetMatcher()
        self.assertFalse(matcher.containsRange(C("1.2.3.4")))
        self.assertFalse(matcher.containsRange(C("132.3.0.0/0")))

        matcher.addRange(C("132.3.0.0/0"))
        self.assertTrue(matcher.containsRange(C("0.0.0.0")))
        self.assertTrue(matcher.containsRange(C("1.2.3.4")))
        self.assertTrue(matcher.containsRange(C("132.3.12.34")))
        self.assertTrue(matcher.containsRange(C("255.255.255.255")))

        matcher.clear()
        matcher.addRange(C("128.210.0.0/15"))
        matcher.addRange(C("128.10.0.0/16"))
        matcher.addRange(C("1.0.0.0/8"))
        self.assertFalse(matcher.containsRange(C("0.0.0.0")))
        self.assertTrue(matcher.containsRange(C("1.2.3.4")))
        self.assertFalse(matcher.containsRange(C("128.209.255.255")))
        self.assertTrue(matcher.containsRange(C("128.210.0.0")))
        self.assertTrue(matcher.containsRange(C("128.211.123.1")))
        self.assertTrue(matcher.containsRange(C("128.211.255.255")))
        self.assertFalse(matcher.containsRange(C("128.212.0.0")))
        self.assertFalse(matcher.containsRange(C("128.9.255.255")))
        self.assertTrue(matcher.containsRange(C("128.10.0.0")))
        self.assertTrue(matcher.containsRange(C("128.10.255.255")))
        self.assertFalse(matcher.containsRange(C("128.11.0.0")))
        self.assertFalse(matcher.containsRange(C("128.210.0.0/14")))
        self.assertTrue(matcher.containsRange(C("128.210.0.0/16")))
        self.assertTrue(matcher.containsRange(C("128.211.0.0/16")))

        self.assertEqual(len(matcher.nets), 3)
        matcher.addRange(C("1.2.3.4/0"))
        matcher.addRange(C("1.2.3.4/5"))
        matcher.addRange(C("128.210.0.0/16"))
        self.assertEqual(len(matcher.nets), 1)
        self.assertTrue(matcher.containsRange(C("0.0.0.0/0")))
        self.assertTrue(matcher.containsRange(C("0.0.0.0/1")))
        self.assertTrue(matcher.containsRange(C("128.0.0.0/1")))
        self.assertTrue(matcher.containsRange(C("0.0.0.0")))
        self.assertTrue(matcher.containsRange(C("127.255.255.255")))
        self.assertTrue(matcher.containsRange(C("128.0.0.0")))
        self.assertTrue(matcher.containsRange(C("255.255.255.255")))

        matcher.clear()
        matcher.addRange(C("0.0.0.0/1"))
        matcher.addRange(C("128.0.0.0/1"))
        self.assertTrue(matcher.containsRange(C("0.0.0.0")))
        self.assertTrue(matcher.containsRange(C("127.255.255.255")))
        self.assertTrue(matcher.containsRange(C("128.0.0.0")))
        self.assertTrue(matcher.containsRange(C("255.255.255.255")))
        self.assertTrue(matcher.containsRange(C("0.0.0.0/1")))
        self.assertTrue(matcher.containsRange(C("128.0.0.0/1")))

        # Does not support aggregation.
        self.assertFalse(matcher.containsRange(C("0.0.0.0/0")))


if __name__ == "__main__":
    unittest.main()
