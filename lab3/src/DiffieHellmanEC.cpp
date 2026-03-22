#include <gmpxx.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "DiffieHellmanEC.h"

typedef mpz_class T;

std::vector<T> fromStrVector(std::vector<std::string> str_a) {
    std::vector<T> a(str_a.size());
    for (size_t i = 0; i < str_a.size(); ++i) {
        a[i] = T(str_a[i], 16);
    }
    return a;
}

std::vector<std::string> toStrVector(GFE<T> gf_a) {
    std::vector<GF<T>> a = gf_a.getValue().getCoefficients();
    std::vector<std::string> str_a(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        str_a[i] = a[i].getValue().get_str(16);
    }
    return str_a;
}

std::pair<std::string, std::string> DHEcpKeyGen(std::string str_p, std::string str_a, std::string str_b, std::string str_g_x, std::string str_g_y, std::string str_q) {
    T p = T(str_p, 16);
    T a = T(str_a, 16);
    T b = T(str_b, 16);
    T g_x = T(str_g_x, 16);
    T g_y = T(str_g_y, 16);
    T q = T(str_q, 16);
    DiffieHellmanEC<T>::EcpKeyGeneration(p, a, b, g_x, g_y, q);
    EC<T> pk = DiffieHellmanEC<T>::getEcpPk();
    return {pk.getX().getValue().get_str(16), pk.getY().getValue().get_str(16)};
}

std::pair<std::string, std::string> DHEcpKeyAgr(std::string str_epk_x, std::string str_epk_y) {
    T epk_x = T(str_epk_x, 16);
    T epk_y = T(str_epk_y, 16);
    DiffieHellmanEC<T>::EcpKeyAgreement(epk_x, epk_y);
    EC<T> shared = DiffieHellmanEC<T>::getEcpShared();
    return {shared.getX().getValue().get_str(16), shared.getY().getValue().get_str(16)};
}

std::pair<std::string, std::string> DHEc2mKeyGen(std::string str_m, std::string str_a, std::string str_b, std::string str_g_x, std::string str_g_y, std::string str_q) {
    T m = T(str_m, 16);
    T a = T(str_a, 16);
    T b = T(str_b, 16);
    T g_x = T(str_g_x, 16);
    T g_y = T(str_g_y, 16);
    T q = T(str_q, 16);
    DiffieHellmanEC<T>::Ec2mKeyGeneration(m, a, b, g_x, g_y, q);
    EC2E<T> pk = DiffieHellmanEC<T>::getEc2mPk();
    return {pk.getX().getValue().get_str(16), pk.getY().getValue().get_str(16)};
}

std::pair<std::string, std::string> DHEc2mKeyAgr(std::string str_epk_x, std::string str_epk_y) {
    T epk_x = T(str_epk_x, 16);
    T epk_y = T(str_epk_y, 16);
    DiffieHellmanEC<T>::Ec2mKeyAgreement(epk_x, epk_y);
    EC2E<T> shared = DiffieHellmanEC<T>::getEc2mShared();
    return {shared.getX().getValue().get_str(16), shared.getY().getValue().get_str(16)};
}

std::pair<std::vector<std::string>, std::vector<std::string>> DHEcpkKeyGen(std::string str_p, const std::vector<std::string>& str_m, const std::vector<std::string>& str_a, const std::vector<std::string>& str_b, const std::vector<std::string>& str_g_x, const std::vector<std::string>& str_g_y, std::string str_q) {
    T p = T(str_p, 16);
    T q = T(str_q, 16);
    std::vector<T> m = fromStrVector(str_m);
    std::vector<T> a = fromStrVector(str_a);
    std::vector<T> b = fromStrVector(str_b);
    std::vector<T> g_x = fromStrVector(str_g_x);
    std::vector<T> g_y = fromStrVector(str_g_y);

    DiffieHellmanEC<T>::EcpkKeyGeneration(p, m, a, b, g_x, g_y, q);
    ECE<T> pk = DiffieHellmanEC<T>::getEcpkPk();
    return {toStrVector(pk.getX()), toStrVector(pk.getY())};
}

std::pair<std::vector<std::string>, std::vector<std::string>> DHEcpkKeyAgr(const std::vector<std::string>& str_epk_x, const std::vector<std::string>& str_epk_y) {
    std::vector<T> epk_x = fromStrVector(str_epk_x);
    std::vector<T> epk_y = fromStrVector(str_epk_y);
    DiffieHellmanEC<T>::EcpkKeyAgreement(epk_x, epk_y);
    ECE<T> shared = DiffieHellmanEC<T>::getEcpkShared();
    return {toStrVector(shared.getX()), toStrVector(shared.getY())};
}

PYBIND11_MODULE(diffie_hellman_ec, m) {
    m.def("DHEcpKeyGen", &DHEcpKeyGen);
    m.def("DHEcpKeyAgr", &DHEcpKeyAgr);
    m.def("DHEc2mKeyGen", &DHEc2mKeyGen);
    m.def("DHEc2mKeyAgr", &DHEc2mKeyAgr);
    m.def("DHEcpkKeyGen", &DHEcpkKeyGen);
    m.def("DHEcpkKeyAgr", &DHEcpkKeyAgr);
}
