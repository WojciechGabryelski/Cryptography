#ifndef DIFFIE_HELLMAN_EC_H
#define DIFFIE_HELLMAN_EC_H

#include "EC.h"
#include "EC2E.h"
#include "ECE.h"

template <typename T>
class DiffieHellmanEC {
private:
    static T ecp_sk;
    static EC<T> ecp_pk;
    static EC<T> ecp_shared;
    static T ec2m_sk;
    static EC2E<T> ec2m_pk;
    static EC2E<T> ec2m_shared;
    static T ecpk_sk;
    static ECE<T> ecpk_pk;
    static ECE<T> ecpk_shared;

    static Polynomial<GF<T>> toPolyGF(std::vector<T> a) {
        std::vector<GF<T>> gf_a(a.size());
        for (size_t i = 0; i < a.size(); ++i) {
            gf_a[i] = GF<T>(a[i]);
        }
        return Polynomial<GF<T>>(gf_a);
    }
public:

    DiffieHellmanEC() {}

    static T getEcpSk() {
        return DiffieHellmanEC<T>::ecp_sk;
    }

    static EC<T> getEcpPk() {
        return DiffieHellmanEC<T>::ecp_pk;
    }

    static EC<T> getEcpShared() {
        return DiffieHellmanEC<T>::ecp_shared;
    }
    
    static T getEc2mSk() {
        return DiffieHellmanEC<T>::ec2m_sk;
    }

    static EC2E<T> getEc2mPk() {
        return DiffieHellmanEC<T>::ec2m_pk;
    }

    static EC2E<T> getEc2mShared() {
        return DiffieHellmanEC<T>::ec2m_shared;
    }

    static T getEcpkSk() {
        return DiffieHellmanEC<T>::ecpk_sk;
    }

    static ECE<T> getEcpkPk() {
        return DiffieHellmanEC<T>::ecpk_pk;
    }

    static ECE<T> getEcpkShared() {
        return DiffieHellmanEC<T>::ecpk_shared;
    }

    static void EcpKeyGeneration(T p, T a, T b, T g_x, T g_y, T q) {
        GF<T>::init(p, false);
        EC<T>::init(GF<T>(a), GF<T>(b));
        EC<T> ecp_g = EC<T>(GF<T>(g_x), GF<T>(g_y));
        PRNG<T> prng = PRNG<T>();
        T q_minus_one = q - (T) 1;
        DiffieHellmanEC<T>::ecp_sk = prng.random((T) 0, q_minus_one);
        DiffieHellmanEC<T>::ecp_pk = ecp_g * DiffieHellmanEC<T>::ecp_sk;
    }

    static void EcpKeyAgreement(T epk_x, T epk_y) {
        DiffieHellmanEC<T>::ecp_shared = EC<T>(GF<T>(epk_x), GF<T>(epk_y)) * DiffieHellmanEC<T>::ecp_sk;
    }

    static void Ec2mKeyGeneration(T m, T a, T b, T g_x, T g_y, T q) {
        GF2E<T>::init(m, false);
        EC2E<T>::init(GF2E<T>(a), GF2E<T>(b));
        EC2E<T> ec2m_g = EC2E<T>(GF2E<T>(g_x), GF2E<T>(g_y));
        PRNG<T> prng = PRNG<T>();
        T q_minus_one = q - (T) 1;
        DiffieHellmanEC<T>::ec2m_sk = prng.random((T) 0, q_minus_one);
        DiffieHellmanEC<T>::ec2m_pk = ec2m_g * DiffieHellmanEC<T>::ec2m_sk;
    }

    static void Ec2mKeyAgreement(T epk_x, T epk_y) {
        DiffieHellmanEC<T>::ec2m_shared = EC2E<T>(GF2E<T>(epk_x), GF2E<T>(epk_y)) * DiffieHellmanEC<T>::ec2m_sk;
    }

    static void EcpkKeyGeneration(T p, std::vector<T> m, std::vector<T> a, std::vector<T> b, std::vector<T> g_x, std::vector<T> g_y, T q) {
        GF<T>::init(p, false);
        GFE<T>::init(DiffieHellmanEC::toPolyGF(m), false);
        GFE<T> gfe_a = GFE<T>(DiffieHellmanEC::toPolyGF(a));
        GFE<T> gfe_b = GFE<T>(DiffieHellmanEC::toPolyGF(b));
        ECE<T>::init(gfe_a, gfe_b);
        GFE<T> gfe_x = GFE<T>(DiffieHellmanEC::toPolyGF(g_x));
        GFE<T> gfe_y = GFE<T>(DiffieHellmanEC::toPolyGF(g_y));
        ECE<T> ecpk_g = ECE<T>(gfe_x, gfe_y);
        PRNG<T> prng = PRNG<T>();
        T q_minus_one = q - (T) 1;
        DiffieHellmanEC<T>::ecpk_sk = prng.random((T) 0, q_minus_one);
        DiffieHellmanEC<T>::ecpk_pk = ecpk_g * DiffieHellmanEC<T>::ecpk_sk;
    }

    static void EcpkKeyAgreement(std::vector<T> epk_x, std::vector<T> epk_y) {
        GFE<T> gfe_x = GFE<T>(DiffieHellmanEC::toPolyGF(epk_x));
        GFE<T> gfe_y = GFE<T>(DiffieHellmanEC::toPolyGF(epk_y));
        ECE<T> ecpk_epk = ECE<T>(gfe_x, gfe_y);
        DiffieHellmanEC<T>::ecpk_shared = ecpk_epk * DiffieHellmanEC<T>::ecpk_sk;
    }
};

template <typename T>
T DiffieHellmanEC<T>::ecp_sk;

template <typename T>
EC<T> DiffieHellmanEC<T>::ecp_pk;

template <typename T>
EC<T> DiffieHellmanEC<T>::ecp_shared;

template <typename T>
T DiffieHellmanEC<T>::ec2m_sk;

template <typename T>
EC2E<T> DiffieHellmanEC<T>::ec2m_pk;

template <typename T>
EC2E<T> DiffieHellmanEC<T>::ec2m_shared;

template <typename T>
T DiffieHellmanEC<T>::ecpk_sk;

template <typename T>
ECE<T> DiffieHellmanEC<T>::ecpk_pk;

template <typename T>
ECE<T> DiffieHellmanEC<T>::ecpk_shared;

#endif // DIFFIE_HELLMAN_EC_H
