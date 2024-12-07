from implementation.encryption.salsa import *
import unittest


class MyTestCase(unittest.TestCase):

    def test_double_round(self):
        first_matrix = [
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000
        ]

        self.assertEqual(double_round(first_matrix), [
            0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
            0x08000090, 0x02402200, 0x00004000, 0x00800000,
            0x00010200, 0x20400000, 0x08008104, 0x00000000,
            0x20500000, 0xa0000040, 0x0008180a, 0x612a8020
        ])

        second_matrix = [
            0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
            0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
            0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
            0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1
        ]

        self.assertEqual(double_round(second_matrix),[0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
                                                            0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
                                                            0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
                                                            0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277])

    def test_column_round(self):
        first_matrix = [
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000001, 0x00000000, 0x00000000, 0x00000000
        ]

        self.assertEqual(column_round(first_matrix), [0x10090288, 0x00000000, 0x00000000, 0x00000000,
                                                                0x00000101, 0x00000000, 0x00000000, 0x00000000,
                                                                0x00020401, 0x00000000, 0x00000000, 0x00000000,
                                                                0x40a04001, 0x00000000, 0x00000000, 0x00000000])

        second_matrix = [
            0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
            0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
            0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
            0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a
        ]

        self.assertEqual(column_round(second_matrix), [0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
                                                            0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
                                                            0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
                                                            0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8])

    def test_row_round(self):
        first_matrix = [
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000001, 0x00000000, 0x00000000, 0x00000000
        ]

        self.assertEqual(row_round(first_matrix), [0x08008145, 0x00000080, 0x00010200, 0x20500000,
                                                        0x20100001, 0x00048044, 0x00000080, 0x00010000,
                                                        0x00000001, 0x00002000, 0x80040000, 0x00000000,
                                                        0x00000001, 0x00000200, 0x00402000, 0x88000100])

        second_matrix = [
            0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
            0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
            0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
            0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a
        ]

        self.assertEqual(row_round(second_matrix), [0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
                                                            0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
                                                            0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
                                                            0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d])


    def test_quarter_round(self):
        self.assertEqual(quarter_round(0x00000000, 0x00000000, 0x00000000, 0x00000000), (0x00000000, 0x00000000, 0x00000000, 0x00000000))
        self.assertEqual(quarter_round(0x00000001, 0x00000000, 0x00000000, 0x00000000), (0x08008145, 0x00000080, 0x00010200, 0x20500000))
        self.assertEqual(quarter_round(0x00000000, 0x00000001, 0x00000000, 0x00000000), (0x88000100, 0x00000001, 0x00000200, 0x00402000))
        self.assertEqual(quarter_round(0x00000000, 0x00000000, 0x00000001, 0x00000000), (0x80040000, 0x00000000, 0x00000001, 0x00002000))
        self.assertEqual(quarter_round(0x00000000, 0x00000000, 0x00000000, 0x00000001), (0x00048044, 0x00000080, 0x00010000, 0x20100001))
        self.assertEqual(quarter_round(0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137), (0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3))
        self.assertEqual(quarter_round(0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b), (0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c))
        # test van onze theorie slide
        self.assertEqual(quarter_round(0xe4971786,0x0096e9c1,0x932f7534,0x27f0d9bb),(0xa1477cd4,0x436e4947,0x99eeef64,0x80e5a210))

    def test_init_matrix(self):
        key = 0x4ff69c8e1e610aa5c72875cd8c7c69c8
        nonce = 0x341f8a2905ca7af8
        position = 17
        key_bytes = key.to_bytes(16, byteorder='big')
        nonce_bytes = nonce.to_bytes(8, byteorder='big')
        # this enkel 128 bits hier
        k1, k2, k3, k4, k5, k6, k7, k8 = split_key(key_bytes)
        k5 = k1
        k6 = k2
        k7 = k3
        k8 = k4
        listify_keys = [k1, k2, k3, k4, k5, k6, k7, k8]
        n1, n2 = check_and_split_nonce(nonce_bytes)
        listify_nonces = [n1, n2]
        c1, c2, c3, c4 = split_constants(len(key_bytes))
        listify_constants = [c1, c2, c3, c4]
        p1, p2 = split_position(position)
        matrix = init_state(listify_keys, listify_nonces, listify_constants, (p1, p2))
        # theorie slide gebruikt 32 byte constante terwijl wij hier onderscheid maken tussen 128 en 256 bit key bij de startende matrix
        self.assertNotEqual(matrix, [0x61707865,0x8e9cf64f,0xa50a611e,0xcd7528c7,
                                  0xc8697c8c,0x3320646e,0x298a1f34,0xf87aca05,
                                  0x00000011,0x00000000,0x79622d32,0x8e9cf64f,
                                  0xa50a611e,0xcd7528c7,0xc8697c8c,0x6b206574])





if __name__ == '__main__':
    unittest.main()
