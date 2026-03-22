#include <random>
#include <iostream>
#include <type_traits>
#include <gmpxx.h>

template <typename T>
class PRNG {
    static_assert(std::is_integral<T>::value || std::is_same<T, mpz_class>::value,
                  "PRNG supports only integral or mpz_class types");

public:
    PRNG() : engine(std::random_device{}()) {}

    explicit PRNG(unsigned int seed) : engine(seed) {}

    template <typename U = T>
    typename std::enable_if<std::is_integral<U>::value, U>::type
    random(U min, U max) {
        std::uniform_int_distribution<U> dist(min, max);
        return dist(engine);
    }

    template <typename U = T>
    typename std::enable_if<std::is_same<U, mpz_class>::value, U>::type
    random(U min, U max) {
        mpz_class result;
        gmp_randclass rand(gmp_randinit_default);
        rand.seed(static_cast<unsigned long>(std::random_device{}()));
        result = rand.get_z_range(max - min + 1) + min;
        return result;
    }

private:
    std::mt19937 engine;
};