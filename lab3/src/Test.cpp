#include <iostream>
#include <gmpxx.h>
#include "ECE.h"
#include "EC2E.h"

typedef mpz_class T;

int main() {
    GF<T>::init((T) 7);
    Polynomial<GF<T>> w = Polynomial<GF<T>>(std::vector<GF<T>>({(T) 1, (T) 1, (T) 0, (T) 1}));
    GFE<T>::init(w);
    GFE<T> a(Polynomial<GF<T>>(std::vector<GF<T>>({(T) 1, (T) 6, (T) 1})));
    GFE<T> b(Polynomial<GF<T>>(std::vector<GF<T>>({(T) 1, (T) 3})));\
    ECE<T>::init(a, b);
    GFE<T> x(Polynomial<GF<T>>(std::vector<GF<T>>({(T) 1, (T) 2})));
    GFE<T> y = (x.pow(3) + a * x + b).sqrt();
    ECE<T> p = ECE(x, y);
    std::cout << "     p = " << p << "\n";
    std::cout << "    2p = " << p.doublePoint() << "\n";
    std::cout << "    3p = " << p * (T) 3 << "\n";
    std::cout << "2p + p = " << p.doublePoint() + p << "\n";
    std::cout << " p - p = " << p - p << "\n";

    GF2E<T>::init((T) 11);
    GF2E<T> c((T) 5);
    GF2E<T> d((T) 2);
    EC2E<T>::init(c, d);
    GF2E<T> t((T) 6);
    GF2E<T> s((T) 3);
    EC2E<T> q = EC2E(t, s);
    std::cout << "     q = " << q << "\n";
    std::cout << "    2q = " << q.doublePoint() << "\n";
    std::cout << "    3q = " << q * (T) 3 << "\n";
    std::cout << "2q + q = " << q.doublePoint() + q << "\n";
    std::cout << " q - q = " << q - q << "\n";
    return 0;
}
