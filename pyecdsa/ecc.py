from hashlib import sha256
from .helper import encode_base58_checksum
import hmac

P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

class FieldElement:
    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = 'Num {} not in field range 0 to {}'.format(num, prime - 1)
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __repr__(self):
        return f'FieldElement_{self.prime}({self.num})'

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot subtract two numbers in different Fields')
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)

    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different Fields')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)

    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in different Fields')
        # use Fermat's Little Theorem:
        # self.num**1 * other.num**(prime-2) % prime
        num = (self.num * pow(other.num, self.prime - 2, self.prime)) % self.prime
        return self.__class__(num, self.prime)
    
class Point:
    def __init__(self, x, y, a, b):
        self.a, self.b, self.x, self.y = a, b, x, y
        if self.x is None and self.y is None: return
        if self.y**2 != self.x**3 + a * x + b:
            raise ValueError(f'({x}, {y}) is not on the curve')
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and self.a == other.a and self.b == other.b
    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError(f'Points {self}, {other} are not on the same curve')
        if self.x is None: return other
        if other.x is None: return self
        if self.x == other.x and self.y != other.y: return self.__class__(None, None, self.a, self.b)
        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
        if self == other:
            s = (3 * self.x**2 + self.a) / (2 * self.y)
            x = s**2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

class S256Point(Point):
    def __init__(self, x, y, a=None, b=None):
        a, b = FieldElement(0, P), FieldElement(7, P)
        if type(x) == int:
            super().__init__(FieldElement(x, P), FieldElement(y, P), a, b)
        else:
            super().__init__(x, y, a, b)
    def __rmul__(self, coefficient):
        coef = coefficient % N
        current, result = self, S256Point(None, None)
        while coef:
            if coef & 1: result += current
            current += current
            coef >>= 1
        return result
    def verify(self, z, sig):
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total = u * G + v * self
        return total.x.num == sig.r
    def sec(self, compressed=True):
        if compressed:
            prefix = b'\x02' if self.y.num % 2 == 0 else b'\x03'
            return prefix + self.x.num.to_bytes(32, 'big')
        return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')
    
    def address(self, compressed=True, testnet=False):
        # Returns the Bitcoin address string
        # Get the SEC format (compressed or uncompressed)
        sec_bin = self.sec(compressed)
        
        # Hash160 (SHA256 then RIPEMD160)
        import hashlib
        h160 = hashlib.new('ripemd160', hashlib.sha256(sec_bin).digest()).digest()
        
        # Add Prefix (0x6f for testnet, 0x00 for mainnet)
        prefix = b'\x6f' if testnet else b'\x00'
        
        # Base58Check Encode (includes checksum)
        from .helper import encode_base58_checksum
        return encode_base58_checksum(prefix + h160)

class Signature:
    def __init__(self, r, s):
        self.r, self.s = r, s
    def der(self):
        def encode_int(v):
            b = v.to_bytes(32, 'big').lstrip(b'\x00')
            if b[0] & 0x80: b = b'\x00' + b
            return bytes([2, len(b)]) + b
        r_bin, s_bin = encode_int(self.r), encode_int(self.s)
        return bytes([0x30, len(r_bin) + len(s_bin)]) + r_bin + s_bin

G = S256Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
              0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

class PrivateKey:
    def __init__(self, secret):
        self.secret = secret
        self.point = secret * G

    def hex(self):
        return '{:x}'.format(self.secret).zfill(64)

    def wif(self, compressed=True, testnet=False):
        # Determine prefix based on network
        prefix = b'\xef' if testnet else b'\x80'
        # Encode secret to bytes
        secret_bytes = self.secret.to_bytes(32, 'big')
        # Append 0x01 if compressed
        suffix = b'\x01' if compressed else b''
        return encode_base58_checksum(prefix + secret_bytes + suffix)
    