#include <gmpxx.h>
#include "GFE.h"
#include "GF2E.h"
#include <chrono>

typedef mpz_class T;

int main() {
    GF<T>::init((T) 8821);
    std::cout << "Liczba 121 " << (GF<T>::isPrime((T) 121) ? "" : "nie ") << "jest pierwsza\n";
    std::cout << "Liczba 127 " << (GF<T>::isPrime((T) 127) ? "" : "nie ") << "jest pierwsza\n";
    GF<T> a((T) 17);
    std::cout << a + a << "\n";
    std::cout << a * a << "\n";
    std::cout << a.pow((T) 2) << "\n";
    std::cout << a.sqrt() << "\n";
    std::cout << a.getOrder() << "\n";

    GF<T>::init((T) 7);
    Polynomial<GF<T>> w = Polynomial<GF<T>>(std::vector<GF<T>>({(T) 1, (T) 1, (T) 0, (T) 1}));
    GFE<T>::init(w);
    std::cout << "Wielomian x^4+6x^3+4x^2+6x+1 " << (GFE<T>::isIrreducible(Polynomial<GF<T>>(std::vector<GF<T>>({(T) 1, (T) 6, (T) 4, (T) 6, (T) 1}))) ? "nie " : "") << "jest rozkładalny nad ciałem modulo 7\n";
    std::cout << "Wielomian x^3+x^2+1 " << (GFE<T>::isIrreducible(Polynomial<GF<T>>(std::vector<GF<T>>({(T) 1, (T) 0, (T) 1, (T) 1}))) ? "nie " : "") << "jest rozkładalny nad ciałem modulo 7\n";
    Polynomial<GF<T>> u = Polynomial<GF<T>>(std::vector<GF<T>>({(T) 1, (T) 0, (T) 1}));
    Polynomial<GF<T>> v = Polynomial<GF<T>>(std::vector<GF<T>>({(T) 1, (T) 1}));
    std::cout << "w = " << w << ", f = " << u << ", g = " << v << "\n";
    GFE<T> f = GFE<T>(u);
    GFE<T> g = GFE<T>(v);
    std::cout << "f + g = " << f + g << "\n";
    std::cout << "f * g = " << f * g << "\n";
    std::cout << "f / g = " << f / g << "\n";
    std::cout << "g^{-1} = " << g.inv() << "\n";
    std::cout << "f * g^{-1} = " << f * g.inv() << "\n";
    std::cout << "g * g^{-1} = " << g * g.inv() << "\n";
    std::cout << "g^{-70000004} = " << g.pow((T) -70000004) << "\n";
    std::cout << "g^{-70000004} = " << g.pow2((T) -70000004) << "\n";
    std::cout << "sqrt(g) = " << g.sqrt() << "\n";
    std::cout << "order of g = " << g.getOrder() << "\n";

    GF2E<T>::init((T) 11);
    std::cout << "Wielomian x^4+x^2+1 " << (GF2E<T>::isIrreducible((T) 21) ? "nie " : "") << "jest rozkładalny nad ciałem modulo 2\n";
    std::cout << "Wielomian x^3+x^2+1 " << (GF2E<T>::isIrreducible((T) 11) ? "nie " : "") << "jest rozkładalny nad ciałem modulo 2\n";
    T u2 = (T) 5;
    T v2 = (T) 3;
    GF2E<T> f2 = GF2E<T>(u2);
    GF2E<T> g2 = GF2E<T>(v2);
    std::cout << "f + g = " << f2 + g2 << "\n";
    std::cout << "f * g = " << f2 * g2 << "\n";
    std::cout << "f / g = " << f2 / g2 << "\n";
    std::cout << "g^{-1} = " << g2.inv() << "\n";
    std::cout << "f * g^{-1} = " << f2 * g2.inv() << "\n";
    std::cout << "f * g^{-1} = " << f2 * g2.inv2() << "\n";
    std::cout << "g * g^{-1} = " << g2 * g2.inv() << "\n";
    std::cout << "g^{-70000004} = " << g2.pow((T) -70000004) << "\n";
    std::cout << "sqrt(g) = " << g2.sqrt() << "\n";
    std::cout << "order of g = " << g2.getOrder() << "\n";
    return 0;
}