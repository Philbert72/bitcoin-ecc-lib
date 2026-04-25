from pyecdsa.ecc import PrivateKey

# 1. Generate a Private Key from a secret integer
secret = 20260329
pk = PrivateKey(secret)

# 2. Derive the Bitcoin Testnet Address (Compressed)
# This demonstrates the full flow: Secret -> Public Key -> Hash160 -> Base58
testnet_address = pk.point.address(compressed=True, testnet=True)
print(f"Secret: {secret}")
print(f"Testnet Address: {testnet_address}")

# 3. Derive the WIF (Wallet Import Format)
wif = pk.wif(compressed=True, testnet=True)
print(f"WIF: {wif}")