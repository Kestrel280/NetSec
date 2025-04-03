import math
import numpy as np
import random
from Crypto.Hash import SHA3_512

def sha3(m, enc=True):
    # Calculates SHA3-512 of m and returns hex digest
    return SHA3_512.new(m.encode('utf-8') if enc else m).hexdigest()

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

    k = 2  # Number of tests to run
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
