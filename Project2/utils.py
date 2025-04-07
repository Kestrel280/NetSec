import math
import numpy as np
import random
import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_512

NBUF_SIZE = 4096        # Buffer size in bytes for socket.recv() calls; DH sends 4096-bit numbers using base16 repr = 1024 chars, so should be at least 2x that

class Node:
    def __init__(self, nid, ip):
        self.nid = nid
        self.ip = ip
        self.time_last_heartbeat = 0
        self.connected = False
        self.busy = False
    def connect(self, sock, key, thread):
        self.sock = sock
        self.key = key
        self.thread = thread
        self.time_last_heartbeat = time.time()
        self.connected = True
    def secure_send(self, plaintext): # TODO add try/except # TODO add heartbeat time check
        assert self.connected, "cannot send to a non-connected node"
        enc = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = enc.encrypt_and_digest(plaintext.encode('utf-8'))
        nonce = enc.nonce
        header = "{},{},{}.".format(len(ciphertext), len(tag), len(nonce)).encode('utf-8')
        omsg = bytearray()
        omsg = omsg + header + ciphertext + tag + nonce
        self.sock.send(omsg)
        return True
    def secure_recv(self): # TODO add try/except
        assert self.connected, "cannot receive from a non-connected node"

        try:
            imsg = self.sock.recv(NBUF_SIZE)
        except TimeoutError:
            return ''
        if (imsg == b''): return ''

        header = imsg.split(b'.')[0].decode('utf-8')
        payload = b'.'.join(imsg.split(b'.')[1:])

        ciphertext_len  = int(header.split(',')[0])
        tag_len         = int(header.split(',')[1])
        nonce_len       = int(header.split(',')[2])
        ciphertext = payload[:ciphertext_len]
        tag             = payload[ciphertext_len : ciphertext_len + tag_len]
        nonce           = payload[ciphertext_len + tag_len :]

        dec = AES.new(self.key, AES.MODE_GCM, nonce)
        plaintext = dec.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        return plaintext

def sha3(m, enc=True):
    # Calculates SHA3-512 of m and returns hex digest
    return SHA3_512.new(m.encode('utf-8') if enc else m).hexdigest()

def generate_prime(lo, hi):
    """ Generates a prime number in the range [lo, hi] """

    low_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
                  71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
                  151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
                  233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
                  317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
                  419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499)

    x = random.randint(lo, hi)
    while True:

        # Check against low primes first
        low_prime_test_passed = True
        for p in low_primes:
            if ((x % p == 0) and (p**2 <= x)): 
                low_prime_test_passed = False
                break 

        # Not divisible by low primes, try Fermat test now
        if low_prime_test_passed:
            if is_prime(x): 
                return x
        x += 1

def gcd(a, b):
    """
    Euclid Algorithm for GCD.
    :param a:
    :param b:
    :return:
    """

    while b != 0:
        t = b
        b = a % b
        a = t

    return a

def fme(b, e, m):
    """
    Performs fast modular exponentiation using exponentiation by squaring / right-to-left binary method.
    :param b: Base
    :param e: Exponent
    :param m: Modulus
    :return: (b^e) % m
    """

    if m == 1: return 0

    r = 1  # Initialize result
    b = b % m

    while e > 0:
        if e % 2 == 1:  # If current LSB of exponent is 0
            r = (r*b) % m
        e = e // 2  # Right-shift exponent by 1
        b = (b**2) % m  # Square base

    return r

def mmi(a, n):
    """
    Modular Multiplicative Inverse. Solves the equation a*t === 1 (mod n) for t using the Extended Euclidean Algorithm.
    :param a:
    :param n:
    :return:
    """

    t, new_t = 0, 1
    r, new_r = n, a

    while new_r != 0:
        q = r // new_r
        (t, new_t) = (new_t, t - q * new_t)
        (r, new_r) = (new_r, r - q * new_r)

    if r > 1:
        return -1  # No multiplicative inverse exists
    elif t < 0:
        t += n

    return t

def is_prime(n):
    """
    Fermat Primality Test. Probabilistic algorithm -- very high likelihood of correct output, but not guaranteed
    :param n:
    :return: True if (probable) prime, False otherwise.
    """

    # For VERY small numbers sqrt(n) < 3, just check directly
    if n in {1, 2, 3, 5, 7}:
        return True
    elif n in {4, 6, 8}:
        return False
    if n < 1000:  # For small numbers, use brute-force test
        if any(map(lambda d: n % d == 0, list(range(2, math.isqrt(n) + 1)))) > 0:  # If n % d == 0 for any d in (2..sqrt(n)), the number is not prime
            return False
        return True

    k = 10  # Number of tests to run
    if k > n - 2:
        k = n - 2

    # Generate k unique numbers in the range (0..n-2)
    try:  # Ideally: use numpy Generators to sample k random numbers from the range. But, it can only handle values so large
        test_numbers = np.random.default_rng().choice(n - 2, size=k, replace=False)
    except OverflowError:  # Otherwise, just use randint(). In very, very rare circumstances, we could accidentally test the same number twice. (We could easily add logic to avoid this; but, since we're already past the integer overflow value, this is EXCEEDINGLY rare)
        test_numbers = [random.randint(0, n-2) for _ in range(k)]

    for d in test_numbers:
        if fme(d, n-1, n) != 1:
            return False
    return True


if __name__ == '__main__':
    print("--- Performing unit tests for NetSec Utils ---\n")

    # [func_name]_tests = (tuple of test cases, where each test case is a tuple of arguments and an expected result)

    gcd_tests = (  # (a, b, Expected Result)
        (5, 7, 1),
        (2**14, 13521351, 1),
        (15, 30, 15),
        (123456789, 987654321, 9),
        (83410843291162101100521913187515316884435, 2127178470699765295663300805992666470, 1194728946172894615)
     )

    fme_tests = (  # (Base, Exponent, Modulus, Expected Result)
        (123_456_789, 987_654_321, 101_010_101, 33_700_204),
        (12_345_678_987_654_321, 98_765_432_123_456_789, 999_999_999_999, 409_628_705_256),
        (111_111_111_111, 999_999_999_999, 123_456_789, 86_121_900),
        (111_111_111_111, 999_999_999_999, 1, 0),
        (2, 10, 999_999_999_999, 2**10),
    )

    mmi_tests = (
        (7,  160, 23),
        (123456789 + 1, 123456789**2, 123456789**2 - 123456789 + 1),  # mmi(n+1, n^2) = n^2 - n + 1, n > 1
        (12839456123678461273, 123789412378, 66392053583),
        (67892367892346789523467856789245678967895, 2347523456723452346785234678945, -1),  # Not invertible
        (67892367892346789523467856789245678967895, 21347523455672324523467852346789452, 19757040326984763915884914190056011)
    )

    is_prime_tests = (  # (Value, Expected Result (True if Prime, False if Composite))
        (3, True),
        (4, False),
        (5, True),
        (31, True),
        (32, False),
        (60, False),
        (1229, True),
        (1230, False),
        (999331, True),
        (3733 * 3733, False),
        (10_888_869_450_418_352_160_768_000_001, True),
        (327414555693498015751146303749141488063642403240171463406883 * 693342667110830181197325401899700641361965863127336680673013, False)  # RSA-120
    )

    # Function unit-tests
    for test in [_ for _ in globals() if _[-6:] == '_tests']:
        func = locals()['_'.join(test.split('_')[:-1])]
        test_cases = locals()[test]
        print("Performing tests for function {}".format(func.__name__))
        for i, test_case in enumerate(test_cases):
            print("\r   Performing test {}/{}...".format(i+1, len(test_cases)), end='')
            args, expected = test_case[:-1], test_case[-1]
            assert (r := func(*args)) == expected, f"{func.__name__} evaluated with argument(s) {args} = {r}; expected {expected}"
        print("\n   Passed {} tests".format(len(test_cases)))
        globals().__delitem__(test)  # Namespace cleanup
        del i, r, expected, args, test_case, test_cases, test  # Namespace cleanup

    print("Performing tests for generate_prime() with 2048-bit numbers, may take a moment...")
    PRIME_TESTS, LO, HI = (3, 2**2048, 2**2049 - 1)
    for i in range(PRIME_TESTS):
        print("\r   Performing test {}/{}...".format(i+1, PRIME_TESTS), end='')
        assert (is_prime(x := generate_prime(LO, HI))), f"generate_prime() created nonprime {x}"
    print("\n   Passed {} tests".format(PRIME_TESTS))
    del PRIME_TESTS, LO, HI, x, i
