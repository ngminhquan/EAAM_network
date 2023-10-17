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