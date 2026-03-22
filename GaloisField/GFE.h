#ifndef GFE_H
#define GFE_H

#include <vector>
#include "ReducibleException.h"
#include "GF.h"
#include "Polynomial.h"

template <typename T>
class GFE {
private:
    Polynomial<GF<T>> value;
    static Polynomial<GF<T>> poly;
    static T order;
    static Polynomial<GF<T>> quad_non_res;
    static Decomposition<T> decomp;
    static std::list<FactorExponentPair<T>> factorization;
    static bool initialized;

    static Polynomial<GF<T>> getQuadraticNonResidue() {
        T zero = (T) 0;
        T one  = (T) 1;
        T two  = (T) 2;
        if (GF<T>::getP() == two) {
            return Polynomial<GF<T>>(std::vector<GF<T>>({zero}));
        }
        uint64_t n = GFE::poly.degree();
        std::vector<GF<T>> v(n, zero);
        Polynomial<GF<T>> onePoly = Polynomial<GF<T>>(std::vector<GF<T>>({one}));
        T half_order = GFE::order / two;
        T p_minus_one = GF<T>::getP() - one;
        do {
            for (uint64_t i = 0; i < n; ++i) {
                v[i] = GF<T>::prng.random(zero, p_minus_one);
            }
        } while (GFE(Polynomial<GF<T>>(v)).pow(half_order).value != onePoly);
        return Polynomial<GF<T>>(v);
    }
public:

    GFE() {}

    GFE(const Polynomial<GF<T>>& value) {
        if (!GFE::initialized) {
            throw UninitializedException();
        }
        this->value = value % GFE::poly;
    }

    static Polynomial<GF<T>> getPoly() {
        if (!GFE::initialized) {
            throw UninitializedException();
        }
        return GFE::poly;
    }

    static void init(const Polynomial<GF<T>>& poly, bool checkIrreducibility = true) {
        if (checkIrreducibility && !GFE::isIrreducible(poly)) {
            throw ReducibleException();
        } else {
            GFE::initialized = true;
            GFE::poly = poly;
            GFE::order = Utils::pow<T>(GF<T>::getP(), poly.degree()) - (T) 1;
            GFE::decomp = Utils::getDecomposition<T>(GFE::order, (T) 2);
            GFE::quad_non_res = GFE::getQuadraticNonResidue();
            GFE::factorization = std::list<FactorExponentPair<T>>();
        }
    }

    static bool isIrreducible(const Polynomial<GF<T>>& poly) {
        return GFE::RabinTest(poly);
    }

    static bool RabinTest(const Polynomial<GF<T>>& poly) {
        Polynomial<GF<T>> tmp_poly;
        T tmp_order = GFE::order;
        bool initialized = GFE::initialized;
        if (initialized) {
            tmp_poly = GFE::poly;
            tmp_order = GFE::order;
        } else {
            GFE::initialized = true;
        }
        uint64_t n = poly.degree();
        GFE::poly = poly;
        GFE::order = Utils::pow<T>(GF<T>::getP(), poly.degree()) - (T) 1;
        std::list<FactorExponentPair<uint64_t>> factors = Utils::getFactorization<uint64_t>(n);
        GFE x = GFE(Polynomial<GF<T>>({(T) 0, (T) 1}));
        GFE g = x;
        uint64_t prev_m = 0uL;
        Polynomial<GF<T>> one = Polynomial<GF<T>>(std::vector<GF<T>>({(T) 1}));
        bool couldBeIrreducible = true;
        for (auto it = factors.rbegin(); it != factors.rend(); ++it) {
            uint64_t p = it -> primeFactor;
            uint64_t m = n / p;
            g = g.pow(Utils::pow(GF<T>::getP(), m - prev_m));
            Polynomial<GF<T>> h = Polynomial<GF<T>>::gcd((g - x).getValue(), poly);
            if (h.degree() != 0) {
                couldBeIrreducible = false;
                break;
            }
            prev_m = m;
        }
        if (couldBeIrreducible) {
            g = g.pow(Utils::pow(GF<T>::getP(), n - prev_m));
            couldBeIrreducible = (g - x).getValue() == Polynomial<GF<T>>(std::vector<GF<T>>({(T) 0}));
        }

        if (initialized) {
            GFE::poly = tmp_poly;
            GFE::order = tmp_order;
        } else {
            GFE::initialized = false;
        }
        return couldBeIrreducible;
    }

    Polynomial<GF<T>> getValue() const {
        return value;
    }

    void setValue(const Polynomial<GF<T>>& value) {
        if (!GFE::initialized) {
            throw UninitializedException();
        }
        this->value = value % GFE::poly;
    }

    GFE pow2(T a) const {
        T zero = (T) 0;
        T one  = (T) 1;
        if (a < zero)
            return this->inv().pow2(-a);
        Polynomial<GF<T>> result = Polynomial<GF<T>>(std::vector<GF<T>>({one}));
        Polynomial<GF<T>> b = this->value;
        a %= GFE::order;
        while (a != zero) {
            if ((a & one) == one)
                result = result * b % GFE::poly;
            b = b * b % GFE::poly;
            a >>= 1;
        }
        return GFE(result);
    }

    GFE pow(T a) const {
        T zero = (T) 0;
        T one  = (T) 1;
        if (a < zero)
            return this->inv().pow(-a);
        Polynomial<GF<T>> result = Polynomial<GF<T>>(std::vector<GF<T>>({one}));
        Polynomial<GF<T>> b = this->value;
        Polynomial<GF<T>> temp = result;
        T c = one;
        a %= GFE::order;
        while (c < GFE::order) {
            temp = result * b % GFE::poly;
            result = (a & one) == one ? temp : result;
            b = b * b % GFE::poly;
            a >>= 1;
            c <<= 1;
        }
        return GFE(result);
    }

    GFE inv() const {
        Polynomial<GF<T>> zero = Polynomial<GF<T>>(std::vector<GF<T>>({(T) 0}));
        if (this->value == zero)
            throw ZeroInversionException();
        Polynomial<GF<T>> a = this->value, b = GFE::poly;
        Polynomial<GF<T>> x = zero, tmp;
        Polynomial<GF<T>> xPrev = Polynomial<GF<T>>(std::vector<GF<T>>({(T) 1}));
        Polynomial<GF<T>> yPrev = zero;
        Polynomial<GF<T>> y = Polynomial<GF<T>>(std::vector<GF<T>>({(T) 1}));
        while (b != zero) {
            Polynomial<GF<T>> q = a / b;
            tmp = b;
            b = a - q * b;
            a = tmp;
            tmp = x;
            x = xPrev - q * x;
            xPrev = tmp;
            tmp = y;
            y = yPrev - q * y;
            yPrev = tmp;
        }
        return GFE(xPrev / a);
    }

    GFE inv2() const {
        if (this->value == Polynomial<GF<T>>(std::vector<GF<T>>({(T) 0})))
            throw ZeroInversionException();
        return this->pow(GFE::order - (T) 1);
    }

    GFE operator - () const {
        return GFE(-this->value);
    }

    GFE operator + (const GFE &a) const {
        return GFE(this->value + a.value);
    }

    GFE operator - (const GFE &a) const {
        return GFE(this->value - a.value);
    }

    GFE operator * (const GFE &a) const {
        return GFE((this->value * a.value) % GFE::poly);
    }

    GFE operator / (const GFE &a) const {
        return *this * a.inv();
    }

    GFE sqrt() const {
        T zero = (T) 0;
        T one  = (T) 1;
        T two  = (T) 2;
        GFE gfe_zero = GFE(Polynomial<GF<T>>(std::vector<GF<T>>({zero})));
        if (*this == gfe_zero) {
            return gfe_zero;
        }
        if (GF<T>::getP() == two) {
            return this->pow((GFE::order + one) / two);
        }
        GFE gfe_one = GFE(Polynomial<GF<T>>(std::vector<GF<T>>({one})));
        if (this->pow(GFE::order / two) != gfe_one) {
            fprintf(stderr, "Element is not quadratic residual. Returning zero.\n");
            return gfe_zero;
        }
        unsigned int m = GFE::decomp.exponent;
        T q = GFE::decomp.cofactor;
        GFE z = GFE(GFE::quad_non_res);
        GFE c = z.pow(q);
        GFE t = this->pow(q);
        GFE r = this->pow((q + one) / two);
        while (t != gfe_one) {
            unsigned int i = 0;
            GFE tmp = t;
            do {
                tmp *= tmp;
                ++i;
            } while (tmp != gfe_one);
            GFE b = c;
            for (unsigned int j = 0; j < m - i - 1; ++j) {
                b *= b;
            }
            m = i;
            c = b * b;
            t *= c;
            r *= b;
        }
        return r;
    }

    T getOrder() const {
        T zero = (T) 0;
        T one  = (T) 1;
        T t = GFE::order;
        if (GFE::factorization.empty()) {
            GFE::factorization = Utils::getFactorization<T>(t);
        }
        GFE gfe_one = GFE(Polynomial<GF<T>>(std::vector<GF<T>>({one})));
        for (FactorExponentPair<T> fact_exp_pair : GFE::factorization) {
            t /= Utils::pow<T>(fact_exp_pair.primeFactor, fact_exp_pair.exponent);
            GFE a = this->pow(t);
            while (a != gfe_one) {
                a = a.pow(fact_exp_pair.primeFactor);
                t *= fact_exp_pair.primeFactor;
            }
        }
        return t;
    }

    bool operator == (const GFE &a) const {
        return this->value == a.value;
    }

    bool operator != (const GFE &a) const {
        return this->value != a.value;
    }

    friend std::ostream& operator << (std::ostream &s, const GFE &a) {
        return s << a.value;
    }

    GFE operator += (const GFE &a) {
        return *this = *this + a;
    }

    GFE operator -= (const GFE &a) {
        return *this = *this - a;
    }

    GFE operator *= (const GFE &a) {
        return *this = *this * a;
    }

    GFE operator /= (const GFE &a) {
        return *this = *this / a;
    }
};

template <typename T>
Polynomial<GF<T>> GFE<T>::poly;

template <typename T>
T GFE<T>::order;

template <typename T>
Polynomial<GF<T>> GFE<T>::quad_non_res;

template <typename T>
Decomposition<T> GFE<T>::decomp;

template <typename T>
std::list<FactorExponentPair<T>> GFE<T>::factorization;

template <typename T>
bool GFE<T>::initialized = false;

#endif // GFE_H
