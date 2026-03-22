#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#include "GFE.h"
#include "GF2E.h"

template <typename T>
class DiffieHellman {
private:
    static T modp_sk;
    static GF<T> modp_pk;
    static GF<T> modp_shared;
    static T f2m_sk;
    static GF2E<T> f2m_pk;
    static GF2E<T> f2m_shared;
    static T fpk_sk;
    static GFE<T> fpk_pk;
    static GFE<T> fpk_shared;
public:

    DiffieHellman() {}

    static T getModpSk() {
        return DiffieHellman<T>::modp_sk;
    }

    static GF<T> getModpPk() {
        return DiffieHellman<T>::modp_pk;
    }

    static GF<T> getModpShared() {
        return DiffieHellman<T>::modp_shared;
    }

    static T getF2mSk() {
        return DiffieHellman<T>::f2m_sk;
    }

    static GF2E<T> getF2mPk() {
        return DiffieHellman<T>::f2m_pk;
    }

    static GF2E<T> getF2mShared() {
        return DiffieHellman<T>::f2m_shared;
    }

    static T getFpkSk() {
        return DiffieHellman<T>::fpk_sk;
    }

    static GFE<T> getFpkPk() {
        return DiffieHellman<T>::fpk_pk;
    }

    static GFE<T> getFpkShared() {
        return DiffieHellman<T>::fpk_shared;
    }

    static void DiffieHellmanModpKeyGeneration(T p, T g, T q) {
        GF<T>::init(p, false);
        GF<T> gf_g = GF<T>(g);
        PRNG<T> prng = PRNG<T>();
        T q_minus_one = q - (T) 1;
        DiffieHellman<T>::modp_sk = prng.random((T) 0, q_minus_one);
        DiffieHellman<T>::modp_pk = gf_g.pow(DiffieHellman<T>::modp_sk);
    }

    static void DiffieHellmanModpKeyAgreement(T epk) {
        DiffieHellman<T>::modp_shared = GF<T>(epk).pow(DiffieHellman<T>::modp_sk);
    }

    static void DiffieHellmanF2mKeyGeneration(T m, T g, T q) {
        GF2E<T>::init(m, false);
        GF2E<T> gf2e_g = GF2E<T>(g);
        PRNG<T> prng = PRNG<T>();
        T q_minus_one = q - (T) 1;
        DiffieHellman<T>::f2m_sk = prng.random((T) 0, q_minus_one);
        DiffieHellman<T>::f2m_pk = gf2e_g.pow(DiffieHellman<T>::f2m_sk);
    }

    static void DiffieHellmanF2mKeyAgreement(T epk) {
        DiffieHellman<T>::f2m_shared = GF2E<T>(epk).pow(DiffieHellman<T>::f2m_sk);
    }

    static void DiffieHellmanFpkKeyGeneration(T p, std::vector<T> m, std::vector<T> g, T q) {
        GF<T>::init(p, false);
        std::vector<GF<T>> gf_m(m.size());
        for (size_t i = 0; i < m.size(); ++i) {
            gf_m[i] = GF<T>(m[i]);
        }
        GFE<T>::init(Polynomial<GF<T>>(gf_m), false);
        std::vector<GF<T>> gf_g(g.size());
        for (size_t i = 0; i < g.size(); ++i) {
            gf_g[i] = GF<T>(g[i]);
        }
        GFE<T> gfe_g = GFE<T>(Polynomial<GF<T>>(gf_g));
        PRNG<T> prng = PRNG<T>();
        T q_minus_one = q - (T) 1;
        DiffieHellman<T>::fpk_sk = prng.random((T) 0, q_minus_one);
        DiffieHellman<T>::fpk_pk = gfe_g.pow(DiffieHellman<T>::fpk_sk);
    }

    static void DiffieHellmanFpkKeyAgreement(std::vector<T> epk) {
        std::vector<GF<T>> gf_epk(epk.size());
        for (size_t i = 0; i < epk.size(); ++i) {
            gf_epk[i] = GF<T>(epk[i]);
        }
        GFE<T> gfe_epk = GFE<T>(Polynomial<GF<T>>(gf_epk));
        DiffieHellman<T>::fpk_shared = gfe_epk.pow(DiffieHellman<T>::fpk_sk);
    }
};

template <typename T>
T DiffieHellman<T>::modp_sk;

template <typename T>
GF<T> DiffieHellman<T>::modp_pk;

template <typename T>
GF<T> DiffieHellman<T>::modp_shared;

template <typename T>
T DiffieHellman<T>::f2m_sk;

template <typename T>
GF2E<T> DiffieHellman<T>::f2m_pk;

template <typename T>
GF2E<T> DiffieHellman<T>::f2m_shared;

template <typename T>
T DiffieHellman<T>::fpk_sk;

template <typename T>
GFE<T> DiffieHellman<T>::fpk_pk;

template <typename T>
GFE<T> DiffieHellman<T>::fpk_shared;

#endif // DIFFIE_HELLMAN_H
