import unittest
from pyecdsa.ecc import S256Point, Signature, PrivateKey, G, N
from pyecdsa.helper import hash256

class TestBitcoinECC(unittest.TestCase):

    def test_problem_1_verification(self):
        """Verify the signature from Problem 1"""
        px = 0xaf5f6e1a85cdd0fec1ea3769ed9658af867a9003729b9dd1737e30292ca17822
        py = 0x35f6db4167fbed2fd3e5f438bcfef6d328346e0e394282e10edc26d4d231c700
        z = 0x385cc6201ac83e06794d6e6805650bbdb97d167cbb5c420712e7d0491e565842
        r = 0x2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22
        s = 0xedf13d0bb14ac45514e13934b39928ed7e2c90a37fc9e484197d227f4c92a3d1
        
        point = S256Point(px, py)
        sig = Signature(r, s)
        
        self.assertTrue(point.verify(z, sig), "Signature verification failed for Problem 1")

    def test_problem_3_sec_formats(self):
        """Verify SEC format generation"""
        pk1 = PrivateKey(20260325)
        expected_3_1 = "04ccb70cd231205c78283ad75aa9e50a6626bff0e5c71ff3c1f60e1e4929391b0447a500e1c6ddf68e87c2ebafb13b66fb00883288e52762f22b5cd7d95db817bb"
        self.assertEqual(pk1.point.sec(compressed=False).hex(), expected_3_1)

        pk2 = PrivateKey(20260326)
        expected_3_2 = "032859a973380769eb909f5243d86741e74b0b63f7054b8671e6955efaee8a5b79"
        self.assertEqual(pk2.point.sec(compressed=True).hex(), expected_3_2)

    def test_problem_4_testnet_address(self):
        """Verify Testnet address generation"""
        pk_secret = 20260327
        pk = PrivateKey(pk_secret)
        address = pk.point.address(compressed=False, testnet=True)
        self.assertEqual(address, "n1LrAjiXgT2HawGKmMHVb5VRVYXvSf9KvF")

    def test_problem_4_wif(self):
        """Verify WIF generation"""
        pk_secret = 20260329
        pk = PrivateKey(pk_secret)
        wif = pk.wif(compressed=True, testnet=True)
        self.assertEqual(wif, "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodNFqEUDtMvAzG")

if __name__ == '__main__':
    unittest.main()