#  Chebyshev polynomial defined on the domain R, where the modulo of
#  the result is taken over a large prime number p
#  Tn(x) = 2x*Tn-1(x) - Tn-2(x) mod p
#         given that T0(x) = 1, T1(x) = x

import numpy as np
import sys

def cbs(n, x, p):
    if n == 0:
        return 1
    elif n == 1:
        return x % p
    elif n % 2 == 0:

        return (2 * cbs(n // 2, x, p) ** 2 - 1) % p
    else:
        return (2 * cbs((n - 1) // 2, x, p) * cbs((n + 1) // 2, x, p) - x) %p

def Tnm2(n, x, p):
    if n == 0:
        return 1
    elif n == 1:
        return x % p
    else:
        e = n - 1
        a11, a12, a21, a22 = 1, 0, 0, 1
        s11, s12, s21, s22 = 0, 1, -1, (2 * x)
        while e > 1:
            if e % 2 == 1:
                t1 = (a11 * s11 + a12 * s21) % p
                a12 = (a11 * s12 + a12 * s22) % p
                a11 = t1
                t2 = (a21 * s11 + a22 * s21) % p
                a22 = (a21 * s12 + a22 * s22) % p
                a21 = t2  
            t1 = s11 + s22
            t2 = s12 * s21
            s11 = (s11 ** 2 + t2) % p
            s12 = (s12 * t1) % p
            s21 = (s21 * t1) % p
            s22 = (s22 ** 2 + t2) % p
            e //=2     
        t1 = (a21 * s11 + a22 * s21) % p
        t2 = (a21 * s12 + a22 * s22) % p
        return (t1 + t2 * x) % p