# Bitcoin ECC Utility Library

A lightweight, pure-Python implementation of the **secp256k1** elliptic curve and Bitcoin serialization protocols. This library serves as a foundational toolset for understanding the cryptographic mechanics behind the Bitcoin network.

## 🚀 Features

* **Finite Field Mathematics**: Custom `FieldElement` implementation for modular arithmetic, including modular inverse and Fermat's Little Theorem.
* **Elliptic Curve Arithmetic**: Point addition and binary expansion scalar multiplication for secp256k1.
* **ECDSA**: Secure signature generation and verification logic.
* **Bitcoin Serialization**:
  * **SEC Format**: Both Compressed and Uncompressed public key formats.
  * **DER Format**: Standardized signature encoding.
  * **Base58Check**: Robust encoding including network prefixes and checksums.
  * **Addresses & WIF**: Support for Mainnet/Testnet addresses and Wallet Import Format.

## 📁 Repository Structure

```text
bitcoin-ecc-lib/
├── pyecdsa/             # Core package logic
│   ├── __init__.py      
│   ├── ecc.py           # Elliptic Curve & PrivateKey classes
│   └── helper.py        # Hashing and Base58 utilities
├── tests/               # Unit testing suite
│   ├── __init__.py
│   └── test_cases.py    
├── examples.py          # Quick-start demonstration script
└── README.md            # Project documentation
```

## 🛠️ Usage

This library requires no external dependencies. You can begin generating keys and addresses immediately:

```python
from pyecdsa.ecc import PrivateKey

# Initialize a private key from a secret
pk = PrivateKey(20260327)

# Generate a compressed Testnet address
print(f"Address: {pk.point.address(compressed=True, testnet=True)}")

# Generate the WIF (Wallet Import Format)
print(f"WIF: {pk.wif(compressed=True, testnet=True)}")
```

To run the provided demonstration:
```bash
python3 examples.py
```

## ✅ Testing

To verify the mathematical correctness and serialization logic against known Bitcoin test vectors:

```bash
python3 -m unittest tests.test_cases
```
