#ifndef GF_H
#define GF_H

#include <iostream>
#include "ZeroInversionException.h"
#include "UninitializedException.h"
#include "CompositeException.h"
#include "PRNG.h"
#include "Utils.h"

template <typename T>
class GF {
private:
    T value;
    static T p;
    static T quad_non_res;
    static Decomposition<T> decomp;
    static std::list<FactorExponentPair<T>> factorization;
    static bool initialized;

    static T getQuadraticNonResidue() {
        T zero = (T) 0;
        T one  = (T) 1;
        T two  = (T) 2;
        if (GF::p == two) {
            return zero;
        }
        T k = two;
        T half_order = (GF::p - one) / two;
        while (GF(k).pow(half_order).value == one) {
            ++k;
        }
        return k;
    }
public:
    static PRNG<T> prng;
    static const uint32_t MILLER_RABIN_ITERATIONS;

    GF() {}

    GF(T value) {
        if (!GF::initialized) {
            throw UninitializedException();
        }
        value = value % GF::p;
        this->value = value < (T) 0 ? value + GF::p : value;
    }

    static T getP() {
        if (!GF::initialized) {
            throw UninitializedException();
        }
        return GF::p;
    }

    static void init(T p, bool checkPrimality = true) {
        if (checkPrimality && !GF::isPrime(p)) {
            throw CompositeException();
        } else {
            GF::initialized = true;
            GF::p = p;
            GF::decomp = Utils::getDecomposition<T>(GF::p - (T) 1, (T) 2);
            GF::quad_non_res = GF::getQuadraticNonResidue();
            GF::factorization = std::list<FactorExponentPair<T>>();
        }
    }

    static bool isPrime(T value) {
        return GF::MillerRabinTest(value);
    }

    static bool MillerRabinTest(T value) {
        T one       = (T) 1;
        T minus_one = (T) -1;

        T tmp_p;
        Decomposition<T> tmp_decomp;
        bool initialized = GF::initialized;
        if (initialized) {
            tmp_p = GF::p;
            tmp_decomp = GF::decomp;
        } else {
            GF::initialized = true;
        }
        GF::p = value;
        GF::decomp = Utils::getDecomposition<T>(GF::p - one, (T) 2);

        GF gf_one = GF(one);
        GF gf_minus_one = GF(minus_one);
        bool couldBePrime = true;
        for (uint32_t i = 0; i < GF::MILLER_RABIN_ITERATIONS; ++i) {
            T val_minus_one = value - one;
            T c = GF::prng.random(one, val_minus_one);
            GF a = GF(c);
            GF pow_a = a.pow(GF::decomp.cofactor);
            if (pow_a != gf_minus_one && pow_a != gf_one) {
                couldBePrime = false;
                for (unsigned int j = 1; j < GF::decomp.exponent; ++j) {
                    pow_a *= pow_a;
                    if (pow_a == gf_minus_one) {
                        couldBePrime = true;
                        break;
                    }
                }
                if (!couldBePrime) {
                    break;
                }
            }
        }

        if (initialized) {
            GF::p = tmp_p;
            GF::decomp = tmp_decomp;
        } else {
            GF::initialized = false;
        }

        return couldBePrime;
    }

    T getValue() const {
        return value;
    }

    void setValue(T value) const {
        if (!GF::initialized) {
            throw UninitializedException();
        }
        value = value % GF::p;
        this->value = value < (T) 0 ? value + GF::p : value;
    }

    GF pow2(T a) const {
        T zero = (T) 0;
        T one  = (T) 1;
        if (a < zero)
            return this->inv().pow2(-a);
        T result = one;
        T b = value;
        a %= GF::p - one;
        while (a > zero) {
            if ((a & one) == one)
                result = result * b % GF::p;
            b = b * b % GF::p;
            a >>= 1;
        }
        return GF(result);
    }

    GF pow(T a) const {
        T zero = (T) 0;
        T one  = (T) 1;
        if (a < zero)
            return this->inv().pow(-a);
        T result = one;
        T b = value;
        T c = one;
        T temp = result;
        T order = GF::p - one;
        a %= order;
        while (c < order) {
            temp = result * b % GF::p;
            result = (a & one) == one ? temp : result;
            b = b * b % GF::p;
            a >>= 1;
            c <<= 1;
        }
        return GF(result);
    }

    GF inv() const {
        T zero = (T) 0;
        if (this->value == zero)
            throw ZeroInversionException();
        T a = this->value, b = GF::p;
        T x = zero, tmp;
        T xPrev = (T) 1;
        while (b) {
            T q = a / b;
            tmp = b;
            b = a - q * b;
            a = tmp;
            tmp = x;
            x = (xPrev - q * x % GF::p + GF::p) % GF::p;
            xPrev = tmp;
        }
        return GF(xPrev);
    }

    GF inv2() const {
        if (this->value == (T) 0)
            throw ZeroInversionException();
        return this->pow(GF::p - (T) 2);
    }

    operator T() {
        return this->value;
    }

    GF operator = (T b) {
        return *this = GF(b);
    }

    GF operator + (const GF &a) const {
        return GF(this->value + a.value);
    }

    GF operator - (const GF &a) const {
        return GF(this->value - a.value);
    }

    GF operator * (const GF &a) const {
        return GF(this->value * a.value);
    }

    GF operator / (const GF &a) const {
        return *this * a.inv();
    }

    GF sqrt() const {
        T zero = (T) 0;
        T one  = (T) 1;
        T two  = (T) 2;
        GF gf_zero = GF(zero);
        if (*this == gf_zero) {
            return gf_zero;
        }
        if (GF::p == two) {
            return GF(this->value);
        }
        GF gf_one = GF(one);
        if (this->pow((GF::p - one) / two) != gf_one) {
            fprintf(stderr, "Element is not quadratic residual. Returning zero.\n");
            return gf_zero;
        }
        unsigned int m = GF::decomp.exponent;
        T q = GF::decomp.cofactor;
        GF z = GF(GF::quad_non_res);
        GF c = z.pow(q);
        GF t = this->pow(q);
        GF r = this->pow((q + one) / two);
        while (t != gf_one) {
            unsigned int i = 0;
            GF tmp = t;
            do {
                tmp *= tmp;
                ++i;
            } while (tmp != gf_one);
            GF b = c;
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
        T t = GF::p - one;
        if (GF::factorization.empty()) {
            GF::factorization = Utils::getFactorization<T>(t);
        }
        GF gf_one = GF(one);
        for (FactorExponentPair<T> fact_exp_pair : GF::factorization) {
            t /= Utils::pow<T>(fact_exp_pair.primeFactor, fact_exp_pair.exponent);
            GF a = this->pow(t);
            while (a != gf_one) {
                a = a.pow(fact_exp_pair.primeFactor);
                t *= fact_exp_pair.primeFactor;
            }
        }
        return t;
    }

    GF operator - () const {
        return GF(-this->value);
    }

    GF operator + (T a) const {
        return *this + GF(a);
    }

    GF operator - (T a) const {
        return *this - GF(a);
    }

    GF operator * (T a) const {
        return *this * GF(a);
    }

    GF operator / (T a) const {
        return *this * GF(a).inv();
    }

    bool operator == (const GF &a) const {
        return this->value == a.value;
    }

    bool operator == (T a) const {
        return *this == GF(a);
    }

    bool operator != (const GF &a) const {
        return this->value != a.value;
    }

    bool operator != (T a) const {
        return *this != GF(a);
    }

    friend std::ostream& operator << (std::ostream &s, const GF &a) {
        return s << a.value;
    }

    friend T operator + (T a, const GF &b) {
        return GF(a) + b;
    }

    friend T operator - (T a, const GF &b) {
        return GF(a) - b;
    }

    friend T operator * (T a, const GF &b) {
        return GF(a) * b;
    }

    friend T operator / (T a, const GF &b) {
        return GF(a) / b;
    }

    GF operator += (const GF &a) {
        return *this = *this + a;
    }

    GF operator -= (const GF &a) {
        return *this = *this - a;
    }

    GF operator *= (const GF &a) {
        return *this = *this * a;
    }

    GF operator /= (const GF &a) {
        return *this = *this / a;
    }

    GF operator += (T a) {
        return *this = *this + a;
    }

    GF operator -= (T a) {
        return *this = *this - a;
    }

    GF operator *= (T a) {
        return *this = *this * a;
    }

    GF operator /= (T a) {
        return *this = *this / a;
    }

    friend T operator += (T &a, const GF &b) {
        return a = a + b;
    }

    friend T operator -= (T &a, const GF &b) {
        return a = a - b;
    }

    friend T operator *= (T &a, const GF &b) {
        return a = a * b;
    }

    friend T operator /= (T &a, const GF &b) {
        return a = a / b;
    }
};

template <typename T>
T GF<T>::p;

template <typename T>
Decomposition<T> GF<T>::decomp;

template <typename T>
T GF<T>::quad_non_res;

template <typename T>
std::list<FactorExponentPair<T>> GF<T>::factorization;

template <typename T>
PRNG<T> GF<T>::prng = PRNG<T>();

template <typename T>
bool GF<T>::initialized = false;

template <typename T>
const uint32_t GF<T>::MILLER_RABIN_ITERATIONS = 40;

#endif // GF_H
