#!/usr/bin/env python
# Tests for dtella/common/util.py

import fix_path
import unittest
import dtella
from dtella.common.util import cmpify_version
from dtella.common.util import validateNick
from dtella.common.util import CHECK


class UtilTestCase(unittest.TestCase):
    def testCmpifyVersion(self):
        self.assertEqual(
            cmpify_version("1.2a.a-3.four"),
            ((1, ''), (2, 'a'), ('a-3',), ('four',)))

        self.assertEqual(
            cmpify_version("000.000.000"),
            cmpify_version("0.0.0"))

        self.assertNotEqual(
            cmpify_version("0.0.0"),
            cmpify_version("0.0"))

        self.assertTrue(
            cmpify_version("SVN") > cmpify_version("999.9.9"))

        self.assertTrue(
            cmpify_version("10.0") > cmpify_version("2.9.1"))

    def testValidateNick(self):
        self.assertEqual(validateNick("P"), "too short")
        self.assertEqual(validateNick(""), "too short")
        self.assertEqual(validateNick("5id"), "must start with a letter")
        self.assertEqual(validateNick("Some$thing"),
                         "contains an invalid character: '$'")
        self.assertEqual(validateNick("Paul"), "")

    def testCHECK(self):
        CHECK(True)
        self.assertRaises(AssertionError, CHECK, False)


if __name__ == "__main__":
    unittest.main()
