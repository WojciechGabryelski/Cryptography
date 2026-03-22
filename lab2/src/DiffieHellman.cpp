#include <gmpxx.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "DiffieHellman.h"

typedef mpz_class T;

std::string DHModpKeyGen(std::string str_p, std::string str_g, std::string str_q) {
    T p = T(str_p, 16);
    T g = T(str_g, 16);
    T q = T(str_q, 16);
    DiffieHellman<T>::DiffieHellmanModpKeyGeneration(p, g, q);
    GF<T> pk = DiffieHellman<T>::getModpPk();
    return pk.getValue().get_str(16);
}

std::string DHModpKeyAgr(std::string str_epk) {
    T epk = T(str_epk, 16);
    DiffieHellman<T>::DiffieHellmanModpKeyAgreement(epk);
    GF<T> shared = DiffieHellman<T>::getModpShared();
    return shared.getValue().get_str(16);
}

std::string DHF2mKeyGen(std::string str_m, std::string str_g, std::string str_q) {
    T m = T(str_m, 16);
    T g = T(str_g, 16);
    T q = T(str_q, 16);
    DiffieHellman<T>::DiffieHellmanF2mKeyGeneration(m, g, q);
    GF2E<T> pk = DiffieHellman<T>::getF2mPk();
    return pk.getValue().get_str(16);
}

std::string DHF2mKeyAgr(std::string str_epk) {
    T epk = T(str_epk, 16);
    DiffieHellman<T>::DiffieHellmanF2mKeyAgreement(epk);
    GF2E<T> shared = DiffieHellman<T>::getF2mShared();
    return shared.getValue().get_str(16);
}

std::vector<std::string> DHFpkKeyGen(std::string str_p, const std::vector<std::string>& str_m, const std::vector<std::string>& str_g, std::string str_q) {
    T p = T(str_p, 16);
    T q = T(str_q, 16);
    std::vector<T> m(str_m.size());
    for (size_t i = 0; i < str_m.size(); ++i) {
        m[i] = T(str_m[i], 16);
    }
    std::vector<T> g(str_g.size());
    for (size_t i = 0; i < str_g.size(); ++i) {
        g[i] = T(str_g[i], 16);
    }

    DiffieHellman<T>::DiffieHellmanFpkKeyGeneration(p, m, g, q);
    GFE<T> pk = DiffieHellman<T>::getFpkPk();
    std::vector<GF<T>> gf_result = pk.getValue().getCoefficients();
    std::vector<std::string> result(gf_result.size());
    for (size_t i = 0; i < gf_result.size(); ++i) {
        result[i] = gf_result[i].getValue().get_str(16);
    }
    return result;
}

std::vector<std::string> DHFpkKeyAgr(const std::vector<std::string>& str_epk) {
    std::vector<T> epk(str_epk.size());
    for (size_t i = 0; i < str_epk.size(); ++i) {
        epk[i] = T(str_epk[i], 16);
    }
    DiffieHellman<T>::DiffieHellmanFpkKeyAgreement(epk);
    GFE<T> shared = DiffieHellman<T>::getFpkShared();
    std::vector<GF<T>> gf_result = shared.getValue().getCoefficients();
    std::vector<std::string> result(gf_result.size());
    for (size_t i = 0; i < gf_result.size(); ++i) {
        result[i] = gf_result[i].getValue().get_str(16);
    }
    return result;
}

PYBIND11_MODULE(diffie_hellman, m) {
    m.def("DHModpKeyGen", &DHModpKeyGen);
    m.def("DHModpKeyAgr", &DHModpKeyAgr);
    m.def("DHF2mKeyGen", &DHF2mKeyGen);
    m.def("DHF2mKeyAgr", &DHF2mKeyAgr);
    m.def("DHFpkKeyGen", &DHFpkKeyGen);
    m.def("DHFpkKeyAgr", &DHFpkKeyAgr);
}
