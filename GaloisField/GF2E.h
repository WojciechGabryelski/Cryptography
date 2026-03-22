#ifndef GF2E_H
#define GF2E_H

#include <iostream>
#include "Utils.h"
#include "ZeroInversionException.h"
#include "UninitializedException.h"
#include "ReducibleException.h"

template <typename T>
class GF2E {
private:
    T value;
    static T poly;
    static uint32_t degree;
    static T order;
    static std::list<FactorExponentPair<T>> factorization;
    static bool initialized;

    static uint32_t getOneOverDegree(T a) {
        uint32_t deg = 0;
        while (a != 0) {
            a >>= 1;
            ++deg;
        }
        return deg;
    }

    static T mulMod(T a, T b) {
        return GF2E::mod(GF2E::mul(a, b));
    }

    static T mul(T a, T b) {
        T zero = (T) 0;
        T one  = (T) 1;
        T result = zero;
        while (b != zero) {
            if ((b & one) == one) {
                result ^= a;
            }
            a <<= 1;
            b >>= 1;
        }
        return result;
    }

    static T mod(T a) {
        T zero = (T) 0;
        T one  = (T) 1;
        uint32_t k = GF2E::getOneOverDegree(a);
        uint32_t deg_b = GF2E::degree + 1;
        if (k < deg_b) {
            return a;
        }
        T b = GF2E::poly << (k - deg_b);
        T c = one << (k - 1);
        while (k >= deg_b) {
            if ((a & c) != zero) {
                a ^= b;
            }
            b >>= 1;
            c >>= 1;
            --k;
        }
        return a;
    }

    static T mod(T a, T b) {
        T zero = (T) 0;
        T one  = (T) 1;
        uint32_t k = GF2E::getOneOverDegree(a);
        uint32_t deg_b = GF2E::getOneOverDegree(b);
        if (k < deg_b) {
            return a;
        }
        b = b << (k - deg_b);
        T c = one << (k - 1);
        while (k >= deg_b) {
            if ((a & c) != zero) {
                a ^= b;
            }
            b >>= 1;
            c >>= 1;
            --k;
        }
        return a;
    }

    static T div(T a, T b) {
        T zero = (T) 0;
        T one  = (T) 1;
        uint32_t k = GF2E::getOneOverDegree(a);
        uint32_t deg_b = GF2E::getOneOverDegree(b);
        if (k < deg_b) {
            return zero;
        }
        b <<= k - deg_b;
        T c = one << (k - 1);
        T result = zero;
        while (k >= deg_b) {
            result <<= 1;
            if ((a & c) != zero) {
                a ^= b;
                result |= one;
            }
            b >>= 1;
            c >>= 1;
            --k;
        }
        return result;
    }

    static T gcd(T a, T b) {
        T zero = (T) 0;
        while (b != zero) {
            a = GF2E::mod(a, b);
            T c = a;
            a = b;
            b = c;
        }
        return a;
    }
public:

    GF2E() {}

    GF2E(T value) {
        if (!GF2E::initialized) {
            throw UninitializedException();
        }

        this->value = GF2E::mod(value);
    }

    static T getPoly() {
        if (!GF2E::initialized) {
            throw UninitializedException();
        }
        return GF2E::poly;
    }

    static void init(T poly, bool checkIrreducibility = true) {
        if (checkIrreducibility && !GF2E::isIrreducible(poly)) {
            throw ReducibleException();
        } else {
            GF2E::initialized = true;
            T one = (T) 1;
            GF2E::poly = poly;
            GF2E::degree = GF2E::getOneOverDegree(poly) - 1;
            GF2E::order = (one << GF2E::degree) - one;
            GF2E::factorization = std::list<FactorExponentPair<T>>();
        }
        
    }

    static bool isIrreducible(const T& poly) {
        return GF2E::RabinTest(poly);
    }

    static bool RabinTest(const T& poly) {
        T one = (T) 1;
        T tmp_poly;
        uint32_t tmp_degree = 0;
        T tmp_order = GF2E::order;
        bool initialized = GF2E::initialized;
        if (initialized) {
            tmp_poly = GF2E::poly;
            tmp_degree = GF2E::degree;
            tmp_order = GF2E::order;
        } else {
            GF2E::initialized = true;
        }
        GF2E::poly = poly;
        GF2E::degree = GF2E::getOneOverDegree(poly) - 1;
        GF2E::order = (one << GF2E::degree) - one;
        uint64_t n = GF2E::degree;
        std::list<FactorExponentPair<uint64_t>> factors = Utils::getFactorization<uint64_t>(n);
        GF2E x = GF2E((T) 2);
        GF2E g = x;
        uint64_t prev_m = 0uL;
        bool couldBeIrreducible = true;
        for (auto it = factors.rbegin(); it != factors.rend(); ++it) {
            uint64_t p = it -> primeFactor;
            uint64_t m = n / p;
            g = g.pow(one << (m - prev_m));
            T h = GF2E::gcd((g - x).getValue(), poly);
            if (h != one) {
                couldBeIrreducible = false;
                break;
            }
            prev_m = m;
        }
        if (couldBeIrreducible) {
            g = g.pow(one << (n - prev_m));
            couldBeIrreducible = (g - x).getValue() == (T) 0;
        }

        if (initialized) {
            GF2E::poly = tmp_poly;
            GF2E::degree = tmp_degree;
            GF2E::order = tmp_order;
        } else {
            GF2E::initialized = false;
        }
        return couldBeIrreducible;
    }

    T getValue() const {
        return value;
    }

    void setValue(T value) const {
        if (!GF2E::initialized) {
            throw UninitializedException();
        }
        this->value = GF2E::mod(value);
    }

    GF2E pow2(T a) const {
        T zero = (T) 0;
        T one  = (T) 1;
        if (a < zero)
            return this->inv().pow2(-a);
        T result = one;
        T b = this->value;
        a %= GF2E::order;
        while (a > zero) {
            if ((a & one) == one)
                result = GF2E::mulMod(result, b);
            b = GF2E::mulMod(b, b);
            a >>= 1;
        }
        return GF2E(result);
    }

    GF2E pow(T a) const {
        T zero = (T) 0;
        T one  = (T) 1;
        if (a < zero)
            return this->inv().pow(-a);
        T result = one;
        T b = this->value;
        T c = one;
        T temp = result;
        a %= GF2E::order;
        while (c < GF2E::order) {
            temp = GF2E::mulMod(result, b);
            result = (a & one) == one ? temp : result;
            b = GF2E::mulMod(b, b);
            a >>= 1;
            c <<= 1;
        }
        return GF2E(result);
    }

    GF2E inv() const {
        T zero = (T) 0;
        if (this->value == zero)
            throw ZeroInversionException();
        T a = this->value, b = GF2E::poly;
        T x = zero, tmp;
        T xPrev = (T) 1;
        while (b != zero) {
            T q = GF2E::div(a, b);
            tmp = b;
            b = a ^ GF2E::mul(q, b);
            a = tmp;
            tmp = x;
            x = xPrev ^ GF2E::mul(q, x);
            xPrev = tmp;
        }
        return GF2E(xPrev);
    }

    GF2E inv2() const {
        if (this->value == (T) 0)
            throw ZeroInversionException();
        return this->pow(GF2E::order - (T) 1);
    }

    GF2E operator - () const {
        return GF2E(this->value);
    }

    GF2E operator + (const GF2E &a) const {
        return GF2E(this->value ^ a.value);
    }

    GF2E operator - (const GF2E &a) const {
        return GF2E(this->value ^ a.value);
    }

    GF2E operator * (const GF2E &a) const {
        return GF2E(GF2E::mulMod(this->value, a.value));
    }

    GF2E operator / (const GF2E &a) const {
        return *this * a.inv();
    }

    GF2E sqrt() const {
        return this->pow((GF2E::order + (T) 1) / (T) 2);
    }

    T getOrder() const {
        T zero = (T) 0;
        T one  = (T) 1;
        T t = GF2E::order;
        if (GF2E::factorization.empty()) {
            GF2E::factorization = Utils::getFactorization<T>(t);
        }
        GF2E gf2e_one = GF2E(one);
        for (FactorExponentPair<T> fact_exp_pair : GF2E::factorization) {
            t /= Utils::pow<T>(fact_exp_pair.primeFactor, fact_exp_pair.exponent);
            GF2E a = this->pow(t);
            while (a != gf2e_one) {
                a = a.pow(fact_exp_pair.primeFactor);
                t *= fact_exp_pair.primeFactor;
            }
        }
        return t;
    }

    bool operator == (const GF2E &a) const {
        return this->value == a.value;
    }

    bool operator != (const GF2E &a) const {
        return this->value != a.value;
    }

    friend std::ostream& operator << (std::ostream &s, const GF2E &a) {
        int k = 0;
        T zero = (T) 0;
        T one  = (T) 1;
        T value = a.getValue();
        bool somethingPrinted = false;
        while (value != zero) {
            if ((value & one) == one) {
                if (k == 0) {
                    s << "1";
                } else {
                    if (somethingPrinted) {
                        s << "+";
                    }
                    if (k == 1) {
                        s << "x";
                    } else {
                        s << "x^" << k;
                    }
                }
                somethingPrinted = true;
            }
            value >>= 1;
            ++k;
        }
        if (!somethingPrinted) {
            s << "0";
        }
        return s;
    }

    GF2E operator += (const GF2E &a) {
        return *this = *this + a;
    }

    GF2E operator -= (const GF2E &a) {
        return *this = *this - a;
    }

    GF2E operator *= (const GF2E &a) {
        return *this = *this * a;
    }

    GF2E operator /= (const GF2E &a) {
        return *this = *this / a;
    }
};

template <typename T>
T GF2E<T>::poly;

template <typename T>
uint32_t GF2E<T>::degree;

template <typename T>
T GF2E<T>::order;

template <typename T>
std::list<FactorExponentPair<T>> GF2E<T>::factorization;

template <typename T>
bool GF2E<T>::initialized = false;

#endif // GF2E_H
