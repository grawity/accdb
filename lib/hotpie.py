# Based on <https://github.com/gingerlime/hotpie>, which is:
#
# Copyright (C) 2010 Yoav Aner
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import hmac
import hashlib
import struct
import time
import unittest


def HOTP(K, C, digits=6):
    """
    HOTP accepts key K and counter C
    optional digits parameter can control the response length

    returns the OATH integer code with {digits} length
    """
    C_bytes = struct.pack(b"!Q", C)
    hmac_sha1 = hmac.new(key=K, msg=C_bytes,
                         digestmod=hashlib.sha1).hexdigest()
    return Truncate(hmac_sha1)[-digits:]


def TOTP(K, digits=6, window=30):
    """
    TOTP is a time-based variant of HOTP.
    It accepts only key K, since the counter is derived from the current time
    optional digits parameter can control the response length
    optional window parameter controls the time window in seconds

    returns the OATH integer code with {digits} length
    """
    C = int(time.time() / window)
    return HOTP(K, C, digits=digits)


def Truncate(hmac_sha1):
    """
    Truncate represents the function that converts an HMAC-SHA-1
    value into an HOTP value as defined in Section 5.3.
    http://tools.ietf.org/html/rfc4226#section-5.3
    """
    offset = int(hmac_sha1[-1], 16)
    binary = int(hmac_sha1[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff
    return str(binary)


class HotpTest(unittest.TestCase):
    """
    a very simple test case for HOTP.
    Based on test vectors from http://www.ietf.org/rfc/rfc4226.txt
    """
    def setUp(self):
        self.key_string = b'12345678901234567890'

    def test_hotp_vectors(self):
        hotp_result_vector = ['755224', '287082', '359152',
                              '969429', '338314', '254676',
                              '287922', '162583', '399871',
                              '520489']
        for i, r in enumerate(hotp_result_vector):
            self.assertEqual(HOTP(self.key_string, i), r)

    def test_totp(self):
        """
        a simple test for TOTP.
        since TOTP depends on the time window, we cannot predict the value.
        However, if we execute it several times, we should expect the
        same response most of the time.
        We only expect the value to change
        once or not at all within a reasonable time window.
        """
        value = TOTP(self.key_string, digits=8, window=20)
        value_changes = 0  # counting the number of changes to TOTP value
        for i in range(0, 100000):
            new_totp = TOTP(self.key_string, digits=8, window=20)
            if new_totp != value:
                value_changes += 1
                value = new_totp
        self.assertTrue(value_changes <= 1)

if __name__ == '__main__':
    unittest.main()
