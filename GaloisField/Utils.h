#ifndef UTILS_H
#define UTILS_H

#include <list>

template <typename T>
struct Decomposition {
    T cofactor;
    T primeFactor;
    unsigned int exponent;
};

template <typename T>
struct FactorExponentPair {
    T primeFactor;
    unsigned int exponent;
};

class Utils {
public:
    template <typename T>
    static T pow(T a, unsigned int b) {
        T result = (T) 1;
        while (b != 0) {
            if ((b & 1) == 1) {
                result *= a;
            }
            a *= a;
            b >>= 1;
        }
        return result;
    }

    template <typename T>
    static T getFloorSqrt(T b) {
        T a = 0;
        while (a < b) {
            T c = (a + b + (T) 1) / 2;
            if (c * c < b) {
                a = c;
            } else if (c * c > b) {
                b = c - 1;
            } else {
                return c;
            }
        }
        return a;
    }

    template <typename T>
    static Decomposition<T> getDecomposition(T value, T primeFactor) {
        unsigned int exponent = 0;
        T zero = (T) 0;
        while (value % primeFactor == zero) {
            value /= primeFactor;
            ++exponent;
        }
        return Decomposition<T>{value, primeFactor, exponent};
    }

    template <typename T>
    static std::list<FactorExponentPair<T>> getFactorization(T value) {
        std::list<FactorExponentPair<T>> factorization;
        Decomposition<T> decomp;
        FactorExponentPair<T> fact_exp_pair;
        T zero  = (T) 0;
        T two   = (T) 2;
        T three = (T) 3;
        T four  = (T) 4;
        if (value % two == zero) {
            decomp = Utils::getDecomposition<T>(value, two);
            fact_exp_pair = FactorExponentPair<T>({decomp.primeFactor, decomp.exponent});
            factorization.push_back(fact_exp_pair);
            value = decomp.cofactor;
        }
        if (value % three == zero) {
            decomp = Utils::getDecomposition<T>(value, three);
            fact_exp_pair = FactorExponentPair<T>({decomp.primeFactor, decomp.exponent});
            factorization.push_back(fact_exp_pair);
            value = decomp.cofactor;
        }
        T sqrt = Utils::getFloorSqrt<T>(value);
        T factor = (T) 5;
        bool b = true;
        while (factor <= sqrt) {
            if (value % factor == zero) {
                decomp = Utils::getDecomposition<T>(value, factor);
                fact_exp_pair = FactorExponentPair<T>({decomp.primeFactor, decomp.exponent});
                factorization.push_back(fact_exp_pair);
                value = decomp.cofactor;
                sqrt = Utils::getFloorSqrt<T>(value);
            }
            if (b) {
                factor += two;
                b = false;
            } else {
                factor += four;
                b = true;
            }
        }
        if (value > four) {
            factorization.push_back(FactorExponentPair<T>({value, 1}));
        }
        return factorization;
    }

    template <typename T>
    static bool simplePrimalityTest(T value) {
        T zero  = (T) 0;
        T two   = (T) 2;
        T three = (T) 3;
        T four  = (T) 4;
        if (value % two == zero || value % three == zero) {
            return false;
        }
        T sqrt = Utils::getFloorSqrt<T>(value);
        T factor = (T) 5;
        bool b = true;
        while (factor <= sqrt) {
            if (value % factor == zero) {
                return false;
            }
            if (b) {
                factor += two;
                b = false;
            } else {
                factor += four;
                b = true;
            }
        }
        return true;
    }
};

#endif // UTILS_H
