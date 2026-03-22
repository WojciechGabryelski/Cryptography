#include <gmpxx.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "SchnorrSignature.h"

typedef mpz_class T;

std::vector<T> fromStrVector(const std::vector<std::string>& str_a) {
    std::vector<T> a(str_a.size());
    for (size_t i = 0; i < str_a.size(); ++i) {
        a[i] = T(str_a[i], 16);
    }
    return a;
}

std::vector<std::string> toStrVector(const GFE<T>& gf_a) {
    std::vector<GF<T>> a = gf_a.getValue().getCoefficients();
    std::vector<std::string> str_a(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        str_a[i] = a[i].getValue().get_str(16);
    }
    return str_a;
}

std::string SSModpKeyGen(const std::string& str_p, const std::string& str_g, const std::string& str_q, int bits) {
    T p = T(str_p, 16);
    T g = T(str_g, 16);
    T q = T(str_q, 16);
    SchnorrSignature<T>::ModpKeyGeneration(p, g, q, bits);
    GF<T> pk = SchnorrSignature<T>::getModpPk();
    return pk.getValue().get_str(16);
}

std::pair<std::string, std::string> SSModpSign(const std::string& M) {
    std::pair<T, T> signature = SchnorrSignature<T>::ModpSign(M);
    return {signature.first.get_str(16), signature.second.get_str(16)};
}

bool SSModpVerify(const std::pair<std::string, std::string>& str_signature, const std::string& M) {
    std::pair<T, T> signature = {T(str_signature.first, 16), T(str_signature.second, 16)};
    return SchnorrSignature<T>::ModpVerify(signature, M);
}

void SSModpSetPublicKey(const std::string& str_pk) {
    T pk = T(str_pk, 16);
    SchnorrSignature<T>::setModpPk(pk);
}

std::string SSF2mKeyGen(const std::string& str_m, const std::string& str_g, const std::string& str_q, int bits) {
    T m = T(str_m, 16);
    T g = T(str_g, 16);
    T q = T(str_q, 16);
    SchnorrSignature<T>::F2mKeyGeneration(m, g, q, bits);
    GF2E<T> pk = SchnorrSignature<T>::getF2mPk();
    return pk.getValue().get_str(16);
}

std::pair<std::string, std::string> SSF2mSign(const std::string& M) {
    std::pair<T, T> signature = SchnorrSignature<T>::F2mSign(M);
    return {signature.first.get_str(16), signature.second.get_str(16)};
}

bool SSF2mVerify(const std::pair<std::string, std::string>& str_signature, const std::string& M) {
    std::pair<T, T> signature = {T(str_signature.first, 16), T(str_signature.second, 16)};
    return SchnorrSignature<T>::F2mVerify(signature, M);
}

void SSF2mSetPublicKey(const std::string& str_pk) {
    T pk = T(str_pk, 16);
    SchnorrSignature<T>::setF2mPk(pk);
}

std::vector<std::string> SSFpkKeyGen(const std::string&str_p, const std::vector<std::string>& str_m, const std::vector<std::string>& str_g, const std::string& str_q, int bits) {
    T p = T(str_p, 16);
    std::vector<T> m = fromStrVector(str_m);
    std::vector<T> g = fromStrVector(str_g);
    T q = T(str_q, 16);
    SchnorrSignature<T>::FpkKeyGeneration(p, m, g, q, bits);
    GFE<T> pk = SchnorrSignature<T>::getFpkPk();
    return toStrVector(pk);
}

std::pair<std::string, std::string> SSFpkSign(const std::string& M) {
    std::pair<T, T> signature = SchnorrSignature<T>::FpkSign(M);
    return {signature.first.get_str(16), signature.second.get_str(16)};
}

bool SSFpkVerify(const std::pair<std::string, std::string>& str_signature, const std::string& M) {
    std::pair<T, T> signature = {T(str_signature.first, 16), T(str_signature.second, 16)};
    return SchnorrSignature<T>::FpkVerify(signature, M);
}

void SSFpkSetPublicKey(const std::vector<std::string>& str_pk) {
    std::vector<T> pk = fromStrVector(str_pk);
    SchnorrSignature<T>::setFpkPk(pk);
}

std::pair<std::string, std::string> SSEcpKeyGen(const std::string& str_p, const std::string& str_a, const std::string& str_b, const std::string& str_g_x, const std::string& str_g_y, const std::string& str_q, int bits) {
    T p = T(str_p, 16);
    T q = T(str_q, 16);
    T a = T(str_a, 16);
    T b = T(str_b, 16);
    T g_x = T(str_g_x, 16);
    T g_y = T(str_g_y, 16);

    SchnorrSignature<T>::EcpKeyGeneration(p, a, b, g_x, g_y, q, bits);
    EC<T> pk = SchnorrSignature<T>::getEcpPk();
    return {pk.getX().getValue().get_str(16), pk.getY().getValue().get_str(16)};
}

std::pair<std::string, std::string> SSEcpSign(const std::string& M) {
    std::pair<T, T> signature = SchnorrSignature<T>::EcpSign(M);
    return {signature.first.get_str(16), signature.second.get_str(16)};
}

bool SSEcpVerify(const std::pair<std::string, std::string>& str_signature, const std::string& M) {
    std::pair<T, T> signature = {T(str_signature.first, 16), T(str_signature.second, 16)};
    return SchnorrSignature<T>::EcpVerify(signature, M);
}

void SSEcpSetPublicKey(const std::string& str_pk_x, const std::string& str_pk_y) {
    T pk_x = T(str_pk_x, 16);
    T pk_y = T(str_pk_y, 16);
    SchnorrSignature<T>::setEcpPk(pk_x, pk_y);
}

std::pair<std::string, std::string> SSEc2mKeyGen(const std::string& str_m, const std::string& str_a, const std::string& str_b, const std::string& str_g_x, const std::string& str_g_y, const std::string& str_q, int bits) {
    T m = T(str_m, 16);
    T q = T(str_q, 16);
    T a = T(str_a, 16);
    T b = T(str_b, 16);
    T g_x = T(str_g_x, 16);
    T g_y = T(str_g_y, 16);

    SchnorrSignature<T>::Ec2mKeyGeneration(m, a, b, g_x, g_y, q, bits);
    EC2E<T> pk = SchnorrSignature<T>::getEc2mPk();
    return {pk.getX().getValue().get_str(16), pk.getY().getValue().get_str(16)};
}

std::pair<std::string, std::string> SSEc2mSign(const std::string& M) {
    std::pair<T, T> signature = SchnorrSignature<T>::Ec2mSign(M);
    return {signature.first.get_str(16), signature.second.get_str(16)};
}

bool SSEc2mVerify(const std::pair<std::string, std::string>& str_signature, const std::string& M) {
    std::pair<T, T> signature = {T(str_signature.first, 16), T(str_signature.second, 16)};
    return SchnorrSignature<T>::Ec2mVerify(signature, M);
}

void SSEc2mSetPublicKey(const std::string& str_pk_x, const std::string& str_pk_y) {
    T pk_x = T(str_pk_x, 16);
    T pk_y = T(str_pk_y, 16);
    SchnorrSignature<T>::setEc2mPk(pk_x, pk_y);
}

std::pair<std::vector<std::string>, std::vector<std::string>> SSEcpkKeyGen(const std::string& str_p, const std::vector<std::string>& str_m, const std::vector<std::string>& str_a, const std::vector<std::string>& str_b, const std::vector<std::string>& str_g_x, const std::vector<std::string>& str_g_y, const std::string& str_q, int bits) {
    T p = T(str_p, 16);
    T q = T(str_q, 16);
    std::vector<T> m = fromStrVector(str_m);
    std::vector<T> a = fromStrVector(str_a);
    std::vector<T> b = fromStrVector(str_b);
    std::vector<T> g_x = fromStrVector(str_g_x);
    std::vector<T> g_y = fromStrVector(str_g_y);

    SchnorrSignature<T>::EcpkKeyGeneration(p, m, a, b, g_x, g_y, q, bits);
    ECE<T> pk = SchnorrSignature<T>::getEcpkPk();
    return {toStrVector(pk.getX()), toStrVector(pk.getY())};
}

std::pair<std::string, std::string> SSEcpkSign(const std::string& M) {
    std::pair<T, T> signature = SchnorrSignature<T>::EcpkSign(M);
    return {signature.first.get_str(16), signature.second.get_str(16)};
}

bool SSEcpkVerify(const std::pair<std::string, std::string>& str_signature, const std::string& M) {
    std::pair<T, T> signature = {T(str_signature.first, 16), T(str_signature.second, 16)};
    return SchnorrSignature<T>::EcpkVerify(signature, M);
}

void SSEcpkSetPublicKey(const std::vector<std::string>& str_pk_x, const std::vector<std::string>& str_pk_y) {
    std::vector<T> pk_x = fromStrVector(str_pk_x);
    std::vector<T> pk_y = fromStrVector(str_pk_y);
    SchnorrSignature<T>::setEcpkPk(pk_x, pk_y);
}

PYBIND11_MODULE(schnorr_signature, m) {
    m.def("SSModpKeyGen", &SSModpKeyGen);
    m.def("SSModpSign", &SSModpSign);
    m.def("SSModpVerify", &SSModpVerify);
    m.def("SSModpSetPublicKey", &SSModpSetPublicKey);
    m.def("SSF2mKeyGen", &SSF2mKeyGen);
    m.def("SSF2mSign", &SSF2mSign);
    m.def("SSF2mVerify", &SSF2mVerify);
    m.def("SSF2mSetPublicKey", &SSF2mSetPublicKey);
    m.def("SSFpkKeyGen", &SSFpkKeyGen);
    m.def("SSFpkSign", &SSFpkSign);
    m.def("SSFpkVerify", &SSFpkVerify);
    m.def("SSFpkSetPublicKey", &SSFpkSetPublicKey);
    m.def("SSEcpKeyGen", &SSEcpKeyGen);
    m.def("SSEcpSign", &SSEcpSign);
    m.def("SSEcpVerify", &SSEcpVerify);
    m.def("SSEcpSetPublicKey", &SSEcpSetPublicKey);
    m.def("SSEc2mKeyGen", &SSEc2mKeyGen);
    m.def("SSEc2mSign", &SSEc2mSign);
    m.def("SSEc2mVerify", &SSEc2mVerify);
    m.def("SSEc2mSetPublicKey", &SSEc2mSetPublicKey);
    m.def("SSEcpkKeyGen", &SSEcpkKeyGen);
    m.def("SSEcpkSign", &SSEcpkSign);
    m.def("SSEcpkVerify", &SSEcpkVerify);
    m.def("SSEcpkSetPublicKey", &SSEcpkSetPublicKey);
}
