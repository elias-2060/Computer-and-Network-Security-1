from implementation.authentication.mac import *
import unittest


class MyTestCase(unittest.TestCase):
    def test_sha1_mac(self):
        test_key = 'axxgjjpvnon&d'
        test_nonce = 'b' * 64  # (X = 64 for sha-1 or X = 128 for hmac)
        test_content = 'my email address is: xx@uantwerpen.be'
        # (Results are in hex-string format)
        test_sha_1_mac = '951c9d29468008554c8f7960d29178c7a7a727fa'
        out = generate_mac_sha1(test_content.encode(), test_key, test_nonce.encode())
        self.assertEqual(test_sha_1_mac, out)


    def test_sha512_hmac(self):
        test_key_ = 'axxgjjpvnon&d'
        test_nonce_ = 'b' * 128  # (X = 64 for sha-1 or X = 128 for hmac)
        test_content_ = 'my email address is: xx@uantwerpen.be'
        # (Results are in hex-string format)
        hmac_mac_ = 'bf191bfbfc071e3347002d52d62d2d25be7f5f638699ce816e76c4fb930f4b2037aa9fd23953c69e1eccd47f8e04b2d6eb6485dd9c32e1f5d65b14eee0c9d130'

        out = generate_mac_hmac(test_content_.encode(), test_key_, test_nonce_.encode())

        self.assertEqual(hmac_mac_, out)

if __name__ == '__main__':
    unittest.main()
