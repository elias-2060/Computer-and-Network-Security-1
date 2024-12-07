from implementation.encryption.aes import *
import unittest


class MyTestCase(unittest.TestCase):
    def test_aes_encrypt_decrypt(self):
        key = 'password'

        nonce = 'this is a nonce that is too long, cut it where necessary.'
        plaintext = 'this is some text to test AES'
        ciphertext = b'2\xabf.\xed+/\xe5J\x1b \xc1\x1f|\xe5\xb7I\xd4 R\x81\nE\x0b9\xc8\x05\x99\x14\xceW\xcf'

        print("Plaintext: ", plaintext)
        print("Test Encrypted Ciphertext: ", encrypt(plaintext.encode(), key, nonce.encode()))

        print("Ciphertext: ", ciphertext)
        print("Test Decrypted Ciphertext: ", decrypt(ciphertext, key, nonce.encode()).decode())

        self.assertEqual(plaintext, decrypt(encrypt(plaintext.encode(), key, nonce.encode()), key, nonce.encode()).decode())

if __name__ == '__main__':
    unittest.main()
