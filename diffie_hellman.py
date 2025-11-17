import os
import hashlib


def is_prime(n: int, k: int = 40) -> bool:
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = 2 + os.urandom(1)[0] % (n - 3)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate a random prime with specified bit length"""
    while True:
        candidate = os.urandom(bits // 8)
        num = int.from_bytes(candidate, 'big')
        num |= (1 << (bits - 1)) | 1
        if is_prime(num):
            return num


def find_primitive_root(p: int) -> int:
    """Find a primitive root modulo p (or use well-known small root)"""
    if p == 2:
        return 1
    
    for candidate in [2, 3, 5, 7, 11, 13]:
        if pow(candidate, p - 1, p) == 1:
            factors = []
            n = p - 1
            temp = n
            
            d = 2
            while d * d <= temp and d <= 1000:
                if temp % d == 0:
                    if not factors or factors[-1] != d:
                        factors.append(d)
                    while temp % d == 0:
                        temp //= d
                d += 1
            if temp > 1:
                factors.append(temp)
            
            is_root = True
            for factor in factors:
                if pow(candidate, (p - 1) // factor, p) == 1:
                    is_root = False
                    break
            if is_root:
                return candidate
    
    return 2


class DiffieHellman:
    """Diffie-Hellman key exchange (no external libraries)"""
    
    def __init__(self, p: int = None, g: int = None, bits: int = 1024):
        """
        Initialize DH parameters.
        
        Args:
            p: Prime modulus (if None, generates a random one)
            g: Generator/primitive root (if None, finds one for given p)
            bits: Bit length for prime generation (if p is None)
        """
        if p is None:
            self.p = generate_prime(bits)
        else:
            self.p = p
        
        if g is None:
            self.g = find_primitive_root(self.p)
        else:
            self.g = g
        
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self) -> int:
        """Generate private key and compute public key. Returns public key."""
        self.private_key = int.from_bytes(os.urandom(256), 'big') % (self.p - 1)
        if self.private_key < 2:
            self.private_key = 2
        
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.public_key
    
    def compute_shared_secret(self, other_public_key: int) -> int:
        """Compute shared secret given the other party's public key"""
        if self.private_key is None:
            raise RuntimeError("Private key not generated")
        
        shared = pow(other_public_key, self.private_key, self.p)
        return shared
    
    def export_public_params(self) -> dict:
        """Export public parameters (can be shared insecurely)"""
        return {
            'p': self.p,
            'g': self.g,
            'public_key': self.public_key
        }
    
    @classmethod
    def from_public_params(cls, params: dict) -> 'DiffieHellman':
        """Create a DH instance from exported public parameters"""
        dh = cls(p=params['p'], g=params['g'])
        return dh


def derive_des_key(shared_secret: int, salt: bytes = b'DES_KEY_DERIVE') -> str:
    """
    Derive an 8-byte DES key from shared secret.
    
    Args:
        shared_secret: The shared secret from DH key exchange
        salt: Optional salt for key derivation
    
    Returns:
        8-character ASCII string suitable for DES
    """
    secret_bytes = shared_secret.to_bytes(256, 'big')
    
    kdf_input = secret_bytes + salt
    
    hash_rounds = []
    for i in range(2):
        h = hashlib.sha256()
        h.update(kdf_input + i.to_bytes(4, 'big'))
        hash_rounds.append(h.digest())
    
    derived = b''.join(hash_rounds)[:8]
    
    des_key = derived.hex()[:8]
    
    return des_key


if __name__ == "__main__":
    print("=== Diffie-Hellman Key Exchange Demo ===\n")
    
    print("Step 1: Alice and Bob agree on public parameters")
    print("  Generating prime p and primitive root g...")
    alice = DiffieHellman(bits=512)
    print(f"  p (prime):  {alice.p}")
    print(f"  g (generator): {alice.g}\n")
    
    print("Step 2: Alice generates her private key and computes public key")
    alice_pub = alice.generate_keys()
    print(f"  Alice private key: {alice.private_key}")
    print(f"  Alice public key:  {alice_pub}\n")
    
    print("Step 3: Bob gets the public parameters and generates his keys")
    bob_params = alice.export_public_params()
    bob = DiffieHellman.from_public_params(bob_params)
    bob_pub = bob.generate_keys()
    print(f"  Bob private key: {bob.private_key}")
    print(f"  Bob public key:  {bob_pub}\n")
    
    print("Step 4: Both compute shared secret")
    alice_shared = alice.compute_shared_secret(bob_pub)
    bob_shared = bob.compute_shared_secret(alice_pub)
    print(f"  Alice computed shared secret: {alice_shared}")
    print(f"  Bob computed shared secret:   {bob_shared}")
    print(f"  Match: {alice_shared == bob_shared}\n")
    
    print("Step 5: Derive 8-byte DES key from shared secret")
    alice_key = derive_des_key(alice_shared)
    bob_key = derive_des_key(bob_shared)
    print(f"  Alice derived DES key: {alice_key!r}")
    print(f"  Bob derived DES key:   {bob_key!r}")
    print(f"  Keys match: {alice_key == bob_key}")
