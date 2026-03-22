#ifndef SCHNORR_SIGNATURE_H
#define SCHNORR_SIGNATURE_H

#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include "EC.h"
#include "EC2E.h"
#include "ECE.h"

const char base64_url_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

std::string base64_url_encode(const std::string& in) {
    std::string out;
    int val = 0, valb = -6;
    size_t len = in.length();
    unsigned int i = 0;
    for (i = 0; i < len; ++i) {
        unsigned char c = in[i];
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_url_alphabet[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(base64_url_alphabet[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    return out;
}

std::string mpz_to_fixed_size_bytes(const mpz_class& num, size_t fixed_size) {
    size_t count = 0;
    std::vector<unsigned char> buffer(fixed_size, 0);

    mpz_export(
        buffer.data(),        // Destination buffer
        &count,               // Number of bytes written
        1,                    // Most significant byte first
        1,                    // Size of each word (1 byte here)
        1,                    // Most significant word first
        0,                    // No additional padding
        num.get_mpz_t()       // Source mpz_t number
    );

    if (count > fixed_size) {
        throw std::runtime_error("Number exceeds fixed size limit");
    }

    std::string result(fixed_size, 0);
    std::memcpy(&result[fixed_size - count], buffer.data(), count);
    return result;
}

mpz_class hash(const std::string& input, int bits) {
    std::function<const EVP_MD*()> sha;
    switch(bits) {
        case 224:
            sha = EVP_sha224;
            break;
        case 256:
            sha = EVP_sha256;
            break;
        case 384:
            sha = EVP_sha384;
            break;
        case 512:
            sha = EVP_sha512;
            break;
        default:
            perror("Parameter bits should be one of 224, 256, 384 or 512.\n");
            exit(1);
    }

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(context, sha(), nullptr) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to initialize SHA context");
    }

    // Provide the input data to the hash computation
    if (EVP_DigestUpdate(context, input.data(), input.size()) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to update SHA hash");
    }

    // Finalize the hash computation
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength = 0;
    if (EVP_DigestFinal_ex(context, hash, &hashLength) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to finalize SHA hash");
    }

    // Clean up
    EVP_MD_CTX_free(context);

    std::ostringstream ss;
    for (unsigned int i = 0; i < hashLength; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return mpz_class(ss.str(), 16);
}

template <typename T>
class SchnorrSignature {
private:
    static T modp_sk;
    static GF<T> modp_pk;
    static T modp_order;
    static GF<T> modp_g;
    static T modp_p;
    static int modp_bits;

    static T f2m_sk;
    static GF2E<T> f2m_pk;
    static T f2m_order;
    static GF2E<T> f2m_g;
    static T f2m_m;
    static int f2m_bits;

    static T fpk_sk;
    static GFE<T> fpk_pk;
    static T fpk_order;
    static GFE<T> fpk_g;
    static T fpk_p;
    static Polynomial<GF<T>> fpk_m;
    static int fpk_bits;

    static T ecp_sk;
    static EC<T> ecp_pk;
    static T ecp_order;
    static EC<T> ecp_g;
    static T ecp_p;
    static GF<T> ecp_a;
    static GF<T> ecp_b;
    static int ecp_bits;

    static T ec2m_sk;
    static EC2E<T> ec2m_pk;
    static T ec2m_order;
    static EC2E<T> ec2m_g;
    static T ec2m_m;
    static GF2E<T> ec2m_a;
    static GF2E<T> ec2m_b;
    static int ec2m_bits;

    static T ecpk_sk;
    static ECE<T> ecpk_pk;
    static T ecpk_order;
    static ECE<T> ecpk_g;
    static T ecpk_p;
    static Polynomial<GF<T>> ecpk_m;
    static GFE<T> ecpk_a;
    static GFE<T> ecpk_b;
    static int ecpk_bits;

    static uint32_t getOneOverDegree(T a) {
        uint32_t deg = 0;
        while (a != 0) {
            a >>= 1;
            ++deg;
        }
        return deg;
    }

    static Polynomial<GF<T>> toPolyGF(const std::vector<T>& a) {
        std::vector<GF<T>> gf_a(a.size());
        for (size_t i = 0; i < a.size(); ++i) {
            gf_a[i] = GF<T>(a[i]);
        }
        return Polynomial<GF<T>>(gf_a);
    }

    static T hashModp(const GF<T>& r, const std::string& M) {
        int bits = SchnorrSignature::modp_bits;
        std::string str_r = mpz_to_fixed_size_bytes(r.getValue(), bits / 8);
        std::string input = str_r + M;
        return hash(input, bits);
    }

    static T hashF2m(const GF2E<T>& r, const std::string& M) {
        int bits = SchnorrSignature::f2m_bits;
        std::string str_r = mpz_to_fixed_size_bytes(r.getValue(), bits / 8);
        std::string input = str_r + M;
        return hash(input, bits);
    }

    static T hashFpk(const GFE<T>& r, const std::string& M) {
        int bits = SchnorrSignature::fpk_bits;
        int bytes = bits / 8;
        size_t coeffs_num = SchnorrSignature::fpk_m.getCoefficients().size() - 1;
        std::vector<GF<T>> coeffs = r.getValue().getCoefficients();
        std::string str_r(bytes * coeffs_num, 0);
        for (size_t i = 0; i < coeffs.size(); ++i) {
            std::string tmp = mpz_to_fixed_size_bytes(coeffs[i].getValue(), bytes);
            std::memcpy(&str_r[i * bytes], &tmp, bytes);
        }
        std::string input = str_r + M;
        return hash(input, bits);
    }

    static T hashEcp(const EC<T>& r, const std::string& M) {
        int bits = SchnorrSignature::ecp_bits;
        std::string str_x = mpz_to_fixed_size_bytes(r.getX().getValue(), bits / 8);
        std::string str_y = mpz_to_fixed_size_bytes(r.getY().getValue(), bits / 8);
        std::string input = "{\"x\":\"" + base64_url_encode(str_x) + "\",\"y\":\"" + base64_url_encode(str_y) + "\"}" + M;
        return hash(input, bits);
    }

    static T hashEc2m(const EC2E<T>& r, const std::string& M) {
        int bits = SchnorrSignature::ec2m_bits;
        int bytes = (SchnorrSignature::getOneOverDegree(SchnorrSignature::ec2m_m) - 1) / 8 + 1;
        std::string str_x = mpz_to_fixed_size_bytes(r.getX().getValue(), bytes);
        std::reverse(str_x.begin(), str_x.end());
        std::string str_y = mpz_to_fixed_size_bytes(r.getY().getValue(), bytes);
        std::reverse(str_y.begin(), str_y.end());
        std::string input = "{\"x\":\"" + base64_url_encode(str_x) + "\",\"y\":\"" + base64_url_encode(str_y) + "\"}" + M;
        return hash(input, bits);
    }

    static T hashEcpk(const ECE<T>& r, const std::string& M) {
        int bits = SchnorrSignature::ecpk_bits;
        int bytes = bits / 8;
        size_t coeffs_num = SchnorrSignature::ecpk_m.getCoefficients().size() - 1;
        std::vector<GF<T>> coeffsX = r.getX().getValue().getCoefficients();
        std::string str_x;
        for (size_t i = 0; i < coeffsX.size(); ++i) {
            str_x += "\"" + base64_url_encode(mpz_to_fixed_size_bytes(coeffsX[i].getValue(), bytes)) + "\"";
            if (i != coeffs_num - 1) {
                str_x += ",";
            }
        }
        for (size_t i = 0; i < coeffs_num - coeffsX.size(); ++i) {
            str_x += "\"\"";
            if (i != coeffs_num - coeffsX.size() - 1) {
                str_x += ",";
            }
        }
        std::vector<GF<T>> coeffsY = r.getY().getValue().getCoefficients();
        std::string str_y;
        for (size_t i = 0; i < coeffsY.size(); ++i) {
            str_y += "\"" + base64_url_encode(mpz_to_fixed_size_bytes(coeffsY[i].getValue(), bytes)) + "\"";
            if (i != coeffs_num - 1) {
                str_y += ",";
            }
        }
        for (size_t i = 0; i < coeffs_num - coeffsY.size(); ++i) {
            str_y += "\"\"";
            if (i != coeffs_num - coeffsY.size() - 1) {
                str_y += ",";
            }
        }
        std::string input = "{\"x\":[" + str_x + "],\"y\":[" + str_y + "]}" + M;
        return hash(input, bits);
    }
public:

    SchnorrSignature() {}

    static T getModpSk() {
        return SchnorrSignature::modp_sk;
    }

    static void setModpSk(const T& sk) {
        SchnorrSignature::modp_sk = sk;
    }

    static GF<T> getModpPk() {
        return SchnorrSignature::modp_pk;
    }

    static void setModpPk(const T& pk) {
        GF<T>::init(SchnorrSignature::modp_p);
        SchnorrSignature::modp_pk = GF<T>(pk);
    }

    static T getF2mSk() {
        return SchnorrSignature::f2m_sk;
    }

    static void setF2mSk(const T& sk) {
        SchnorrSignature::f2m_sk = sk;
    }

    static GF2E<T> getF2mPk() {
        return SchnorrSignature::f2m_pk;
    }

    static void setF2mPk(const T& pk) {
        GF2E<T>::init(SchnorrSignature::f2m_m);
        SchnorrSignature::f2m_pk = GF2E<T>(pk);
    }

    static T getFpkSk() {
        return SchnorrSignature::fpk_sk;
    }

    static void setFpkSk(const T& sk) {
        SchnorrSignature::fpk_sk = sk;
    }

    static GFE<T> getFpkPk() {
        return SchnorrSignature::fpk_pk;
    }

    static void setFpkPk(const std::vector<T>& pk) {
        GF<T>::init(SchnorrSignature::fpk_p);
        GFE<T>::init(SchnorrSignature::fpk_m);
        SchnorrSignature::fpk_pk = GFE<T>(SchnorrSignature::toPolyGF(pk));
    }

    static T getEcpSk() {
        return SchnorrSignature::ecp_sk;
    }

    static void setEcpSk(const T& sk) {
        SchnorrSignature::ecp_sk = sk;
    }

    static EC<T> getEcpPk() {
        return SchnorrSignature::ecp_pk;
    }

    static void setEcpPk(const T& pk_x, const T& pk_y) {
        GF<T>::init(SchnorrSignature::ecp_p);
        EC<T>::init(SchnorrSignature::ecp_a, SchnorrSignature::ecp_b);
        SchnorrSignature::ecp_pk = EC<T>(GF<T>(pk_x), GF<T>(pk_y));
    }

    static void setEcpPk(const EC<T>& pk) {
        SchnorrSignature::ecp_pk = pk;
    }

    static T getEc2mSk() {
        return SchnorrSignature::ec2m_sk;
    }

    static void setEc2mSk(const T& sk) {
        SchnorrSignature::ec2m_sk = sk;
    }

    static EC2E<T> getEc2mPk() {
        return SchnorrSignature::ec2m_pk;
    }

    static void setEc2mPk(const T& pk_x, const T& pk_y) {
        GF2E<T>::init(SchnorrSignature::ec2m_m);
        EC2E<T>::init(SchnorrSignature::ec2m_a, SchnorrSignature::ec2m_b);
        SchnorrSignature::ec2m_pk = EC2E<T>(GF2E<T>(pk_x), GF2E<T>(pk_y));
    }

    static void setEc2mPk(const EC2E<T>& pk) {
        SchnorrSignature::ec2m_pk = pk;
    }

    static T getEcpkSk() {
        return SchnorrSignature::ecpk_sk;
    }

    static void setEcpkSk(const T& sk) {
        SchnorrSignature::ecpk_sk = sk;
    }

    static ECE<T> getEcpkPk() {
        return SchnorrSignature::ecpk_pk;
    }

    static void setEcpkPk(const std::vector<T>& pk_x, const std::vector<T>& pk_y) {
        GF<T>::init(SchnorrSignature::ecpk_p);
        GFE<T>::init(SchnorrSignature::ecpk_m);
        ECE<T>::init(SchnorrSignature::ecpk_a, SchnorrSignature::ecpk_b);
        SchnorrSignature::ecpk_pk = ECE<T>(GFE<T>(SchnorrSignature::toPolyGF(pk_x)), GFE<T>(SchnorrSignature::toPolyGF(pk_y)));
    }

    static void setEcpkPk(const ECE<T>& pk) {
        SchnorrSignature::ecpk_pk = pk;
    }

    static void ModpKeyGeneration(const T& p, const T& g, const T& q, int bits) {
        if (bits != 224 && bits != 256 && bits != 384 && bits != 512) {
            perror("Parameter bits should be one of 224, 256, 384 or 512.\n");
            exit(1);
        }
        SchnorrSignature::modp_bits = bits;
        SchnorrSignature::modp_p = p;
        GF<T>::init(SchnorrSignature::modp_p, false);

        SchnorrSignature::modp_g = GF<T>(g);
        SchnorrSignature::modp_order = q;
        PRNG<T> prng = PRNG<T>();
        T q_minus_one = q - (T) 1;
        SchnorrSignature<T>::modp_sk = prng.random((T) 0, q_minus_one);
        SchnorrSignature<T>::modp_pk = SchnorrSignature::modp_g.pow(-SchnorrSignature<T>::modp_sk);
    }

    static std::pair<T, T> ModpSign(const std::string& M) {
        GF<T>::init(SchnorrSignature::modp_p, false);

        PRNG<T> prng = PRNG<T>();
        T q_minus_one = SchnorrSignature::modp_order - (T) 1;
        T k = prng.random((T) 0, q_minus_one);
        GF<T> r = SchnorrSignature::modp_g.pow(k);
        T e = SchnorrSignature::hashModp(r, M);
        T s = k + SchnorrSignature::modp_sk * e;
        return {s, e};
    }

    static bool ModpVerify(const std::pair<T, T>& signature, const std::string& M) {
        GF<T>::init(SchnorrSignature::modp_p, false);

        T s = signature.first;
        T e = signature.second;
        GF<T> r_v = SchnorrSignature::modp_g.pow(s) * SchnorrSignature::modp_pk.pow(e);
        T e_v = SchnorrSignature::hashModp(r_v, M);
        return e == e_v;
    }

    static void F2mKeyGeneration(const T& m, const T& g, const T& q, int bits) {
        if (bits != 224 && bits != 256 && bits != 384 && bits != 512) {
            perror("Parameter bits should be one of 224, 256, 384 or 512.\n");
            exit(1);
        }
        SchnorrSignature::f2m_bits = bits;
        SchnorrSignature::f2m_m = m;
        GF2E<T>::init(SchnorrSignature::f2m_m, false);

        SchnorrSignature::f2m_g = GF2E<T>(g);
        SchnorrSignature::f2m_order = q;
        PRNG<T> prng = PRNG<T>();
        T q_minus_one = q - (T) 1;
        SchnorrSignature<T>::f2m_sk = prng.random((T) 0, q_minus_one);
        SchnorrSignature<T>::f2m_pk = SchnorrSignature::f2m_g.pow(-SchnorrSignature<T>::f2m_sk);
    }

    static std::pair<T, T> F2mSign(const std::string& M) {
        GF2E<T>::init(SchnorrSignature::f2m_m, false);

        PRNG<T> prng = PRNG<T>();
        T q_minus_one = SchnorrSignature::f2m_order - (T) 1;
        T k = prng.random((T) 0, q_minus_one);
        GF2E<T> r = SchnorrSignature::f2m_g.pow(k);
        T e = SchnorrSignature::hashF2m(r, M);
        T s = k + SchnorrSignature::f2m_sk * e;
        return {s, e};
    }

    static bool F2mVerify(const std::pair<T, T>& signature, const std::string& M) {
        GF2E<T>::init(SchnorrSignature::f2m_m, false);

        T s = signature.first;
        T e = signature.second;
        GF2E<T> r_v = SchnorrSignature::f2m_g.pow(s) * SchnorrSignature::f2m_pk.pow(e);
        T e_v = SchnorrSignature::hashF2m(r_v, M);
        return e == e_v;
    }

    static void FpkKeyGeneration(const T& p, const std::vector<T>& m, const std::vector<T>& g, const T& q, int bits) {
        if (bits != 224 && bits != 256 && bits != 384 && bits != 512) {
            perror("Parameter bits should be one of 224, 256, 384 or 512.\n");
            exit(1);
        }
        SchnorrSignature::fpk_bits = bits;
        SchnorrSignature::fpk_p = p;
        GF<T>::init(SchnorrSignature::fpk_p, false);
        SchnorrSignature::fpk_m = SchnorrSignature::toPolyGF(m);
        GFE<T>::init(SchnorrSignature::fpk_m, false);

        SchnorrSignature::fpk_g = GFE<T>(SchnorrSignature::toPolyGF(g));
        SchnorrSignature::fpk_order = q;
        PRNG<T> prng = PRNG<T>();
        T q_minus_one = q - (T) 1;
        SchnorrSignature<T>::fpk_sk = prng.random((T) 0, q_minus_one);
        SchnorrSignature<T>::fpk_pk = SchnorrSignature::fpk_g.pow(-SchnorrSignature<T>::fpk_sk);
    }

    static std::pair<T, T> FpkSign(const std::string& M) {
        GF<T>::init(SchnorrSignature::fpk_p, false);
        GFE<T>::init(SchnorrSignature::fpk_m, false);

        PRNG<T> prng = PRNG<T>();
        T q_minus_one = SchnorrSignature::fpk_order - (T) 1;
        T k = prng.random((T) 0, q_minus_one);
        GFE<T> r = SchnorrSignature::fpk_g.pow(k);
        T e = SchnorrSignature::hashFpk(r, M);
        T s = k + SchnorrSignature::fpk_sk * e;
        return {s, e};
    }

    static bool FpkVerify(const std::pair<T, T>& signature, const std::string& M) {
        GF<T>::init(SchnorrSignature::fpk_p, false);
        GFE<T>::init(SchnorrSignature::fpk_m, false);

        T s = signature.first;
        T e = signature.second;
        GFE<T> r_v = SchnorrSignature::fpk_g.pow(s) * SchnorrSignature::fpk_pk.pow(e);
        T e_v = SchnorrSignature::hashFpk(r_v, M);
        return e == e_v;
    }

    static void EcpKeyGeneration(const T& p, const T& a, const T& b, const T& g_x, const T& g_y, const T& q, int bits) {
        if (bits != 224 && bits != 256 && bits != 384 && bits != 512) {
            perror("Parameter bits should be one of 224, 256, 384 or 512.\n");
            exit(1);
        }
        SchnorrSignature::ecp_bits = bits;
        SchnorrSignature::ecp_p = p;
        GF<T>::init(SchnorrSignature::ecp_p, false);
        SchnorrSignature::ecp_a = GF<T>(a);
        SchnorrSignature::ecp_b = GF<T>(b);
        EC<T>::init(SchnorrSignature::ecp_a, SchnorrSignature::ecp_b);

        GF<T> gf_x = GF<T>(g_x);
        GF<T> gf_y = GF<T>(g_y);
        SchnorrSignature::ecp_g = EC<T>(gf_x, gf_y);
        SchnorrSignature::ecp_order = q;
        PRNG<T> prng = PRNG<T>();
        T q_minus_one = q - (T) 1;
        SchnorrSignature<T>::ecp_sk = prng.random((T) 0, q_minus_one);
        SchnorrSignature<T>::ecp_pk = SchnorrSignature::ecp_g * -SchnorrSignature<T>::ecp_sk;
    }

    static std::pair<T, T> EcpSign(const std::string& M) {
        GF<T>::init(SchnorrSignature::ecp_p, false);
        EC<T>::init(SchnorrSignature::ecp_a, SchnorrSignature::ecp_b);

        PRNG<T> prng = PRNG<T>();
        T q_minus_one = SchnorrSignature::ecp_order - (T) 1;
        T k = prng.random((T) 0, q_minus_one);
        EC<T> r = SchnorrSignature::ecp_g * k;
        T e = SchnorrSignature::hashEcp(r, M);
        T s = k + SchnorrSignature::ecp_sk * e;
        // std::cout << std::hex << "r: " << r << "\n";
        // std::cout << std::hex << "r_v: " << SchnorrSignature::ecp_g * s + SchnorrSignature::ecp_pk * e << "\n";
        // std::cout << std::hex << "sk: " << SchnorrSignature::ecp_sk << "\n";
        // std::cout << std::hex << "pk: " << SchnorrSignature::ecp_g * SchnorrSignature::ecp_sk << "\n";
        // std::cout << std::hex << "pk: " << SchnorrSignature::ecp_pk << "\n";
        // std::cout << std::hex << "g: " << SchnorrSignature::ecp_g << "\n";
        // std::cout << std::hex << "e: " << e << "\n";
        // std::cout << std::hex << "s: " << s << "\n";
        return {s, e};
    }

    static bool EcpVerify(const std::pair<T, T>& signature, const std::string& M) {
        GF<T>::init(SchnorrSignature::ecp_p, false);
        EC<T>::init(SchnorrSignature::ecp_a, SchnorrSignature::ecp_b);

        T s = signature.first;
        T e = signature.second;
        EC<T> r_v = SchnorrSignature::ecp_g * s + SchnorrSignature::ecp_pk * e;
        T e_v = SchnorrSignature::hashEcp(r_v, M);
        // std::cout << std::hex << "sk: " << SchnorrSignature::ecp_sk << "\n";
        // std::cout << std::hex << "pk: " << SchnorrSignature::ecp_pk << "\n";
        // std::cout << std::hex << "g: " << SchnorrSignature::ecp_g << "\n";
        // std::cout << std::hex << "e: " << e << "\n";
        // std::cout << std::hex << "s: " << s << "\n";
        return e == e_v;
    }

    static void Ec2mKeyGeneration(const T& m, const T& a, const T& b, const T& g_x, const T& g_y, const T& q, int bits) {
        if (bits != 224 && bits != 256 && bits != 384 && bits != 512) {
            perror("Parameter bits should be one of 224, 256, 384 or 512.\n");
            exit(1);
        }
        SchnorrSignature::ec2m_bits = bits;
        SchnorrSignature::ec2m_m = m;
        GF2E<T>::init(SchnorrSignature::ec2m_m, false);
        SchnorrSignature::ec2m_a = GF2E<T>(a);
        SchnorrSignature::ec2m_b = GF2E<T>(b);
        EC2E<T>::init(SchnorrSignature::ec2m_a, SchnorrSignature::ec2m_b);

        GF2E<T> gf2e_x = GF2E<T>(g_x);
        GF2E<T> gf2e_y = GF2E<T>(g_y);
        SchnorrSignature::ec2m_g = EC2E<T>(gf2e_x, gf2e_y);
        SchnorrSignature::ec2m_order = q;
        PRNG<T> prng = PRNG<T>();
        T q_minus_one = q - (T) 1;
        SchnorrSignature<T>::ec2m_sk = prng.random((T) 0, q_minus_one);
        SchnorrSignature<T>::ec2m_pk = SchnorrSignature::ec2m_g * -SchnorrSignature<T>::ec2m_sk;
    }

    static std::pair<T, T> Ec2mSign(const std::string& M) {
        GF2E<T>::init(SchnorrSignature::ec2m_m, false);
        EC2E<T>::init(SchnorrSignature::ec2m_a, SchnorrSignature::ec2m_b);

        PRNG<T> prng = PRNG<T>();
        T q_minus_one = SchnorrSignature::ec2m_order - (T) 1;
        T k = prng.random((T) 0, q_minus_one);
        EC2E<T> r = SchnorrSignature::ec2m_g * k;
        T e = SchnorrSignature::hashEc2m(r, M);
        T s = k + SchnorrSignature::ec2m_sk * e;
        return {s, e};
    }

    static bool Ec2mVerify(const std::pair<T, T>& signature, const std::string& M) {
        GF2E<T>::init(SchnorrSignature::ec2m_m, false);
        EC2E<T>::init(SchnorrSignature::ec2m_a, SchnorrSignature::ec2m_b);

        T s = signature.first;
        T e = signature.second;
        EC2E<T> r_v = SchnorrSignature::ec2m_g * s + SchnorrSignature::ec2m_pk * e;
        T e_v = SchnorrSignature::hashEc2m(r_v, M);
        return e == e_v;
    }

    static void EcpkKeyGeneration(const T& p, const std::vector<T>& m, const std::vector<T>& a, const std::vector<T>& b, const std::vector<T>& g_x, const std::vector<T>& g_y, const T& q, int bits) {
        if (bits != 224 && bits != 256 && bits != 384 && bits != 512) {
            perror("Parameter bits should be one of 224, 256, 384 or 512.\n");
            exit(1);
        }
        SchnorrSignature::ecpk_bits = bits;
        SchnorrSignature::ecpk_p = p;
        GF<T>::init(SchnorrSignature::ecpk_p, false);
        SchnorrSignature::ecpk_m = SchnorrSignature::toPolyGF(m);
        GFE<T>::init(SchnorrSignature::ecpk_m, false);
        SchnorrSignature::ecpk_a = GFE<T>(SchnorrSignature::toPolyGF(a));
        SchnorrSignature::ecpk_b = GFE<T>(SchnorrSignature::toPolyGF(b));
        ECE<T>::init(SchnorrSignature::ecpk_a, SchnorrSignature::ecpk_b);

        GFE<T> gfe_x = GFE<T>(SchnorrSignature::toPolyGF(g_x));
        GFE<T> gfe_y = GFE<T>(SchnorrSignature::toPolyGF(g_y));
        SchnorrSignature::ecpk_g = ECE<T>(gfe_x, gfe_y);
        SchnorrSignature::ecpk_order = q;
        PRNG<T> prng = PRNG<T>();
        T q_minus_one = q - (T) 1;
        SchnorrSignature<T>::ecpk_sk = prng.random((T) 0, q_minus_one);
        SchnorrSignature<T>::ecpk_pk = SchnorrSignature::ecpk_g * -SchnorrSignature<T>::ecpk_sk;
    }

    static std::pair<T, T> EcpkSign(const std::string& M) {
        GF<T>::init(SchnorrSignature::ecpk_p, false);
        GFE<T>::init(SchnorrSignature::ecpk_m, false);
        ECE<T>::init(SchnorrSignature::ecpk_a, SchnorrSignature::ecpk_b);

        PRNG<T> prng = PRNG<T>();
        T q_minus_one = SchnorrSignature::ecpk_order - (T) 1;
        T k = prng.random((T) 0, q_minus_one);
        ECE<T> r = SchnorrSignature::ecpk_g * k;
        T e = SchnorrSignature::hashEcpk(r, M);
        T s = k + SchnorrSignature::ecpk_sk * e;
        return {s, e};
    }

    static bool EcpkVerify(const std::pair<T, T>& signature, const std::string& M) {
        GF<T>::init(SchnorrSignature::ecpk_p, false);
        GFE<T>::init(SchnorrSignature::ecpk_m, false);
        ECE<T>::init(SchnorrSignature::ecpk_a, SchnorrSignature::ecpk_b);

        T s = signature.first;
        T e = signature.second;
        ECE<T> r_v = SchnorrSignature::ecpk_g * s + SchnorrSignature::ecpk_pk * e;
        T e_v = SchnorrSignature::hashEcpk(r_v, M);
        return e == e_v;
    }
};

template <typename T>
T SchnorrSignature<T>::modp_sk;

template <typename T>
GF<T> SchnorrSignature<T>::modp_pk;

template <typename T>
T SchnorrSignature<T>::modp_order;

template <typename T>
GF<T> SchnorrSignature<T>::modp_g;

template <typename T>
T SchnorrSignature<T>::modp_p;

template <typename T>
int SchnorrSignature<T>::modp_bits;

template <typename T>
T SchnorrSignature<T>::f2m_sk;

template <typename T>
GF2E<T> SchnorrSignature<T>::f2m_pk;

template <typename T>
T SchnorrSignature<T>::f2m_order;

template <typename T>
GF2E<T> SchnorrSignature<T>::f2m_g;

template <typename T>
T SchnorrSignature<T>::f2m_m;

template <typename T>
int SchnorrSignature<T>::f2m_bits;

template <typename T>
T SchnorrSignature<T>::fpk_sk;

template <typename T>
GFE<T> SchnorrSignature<T>::fpk_pk;

template <typename T>
T SchnorrSignature<T>::fpk_order;

template <typename T>
GFE<T> SchnorrSignature<T>::fpk_g;

template <typename T>
T SchnorrSignature<T>::fpk_p;

template <typename T>
Polynomial<GF<T>> SchnorrSignature<T>::fpk_m;

template <typename T>
int SchnorrSignature<T>::fpk_bits;

template <typename T>
T SchnorrSignature<T>::ecp_sk;

template <typename T>
EC<T> SchnorrSignature<T>::ecp_pk;

template <typename T>
T SchnorrSignature<T>::ecp_order;

template <typename T>
EC<T> SchnorrSignature<T>::ecp_g;

template <typename T>
T SchnorrSignature<T>::ecp_p;

template <typename T>
GF<T> SchnorrSignature<T>::ecp_a;

template <typename T>
GF<T> SchnorrSignature<T>::ecp_b;

template <typename T>
int SchnorrSignature<T>::ecp_bits;

template <typename T>
T SchnorrSignature<T>::ec2m_sk;

template <typename T>
EC2E<T> SchnorrSignature<T>::ec2m_pk;

template <typename T>
T SchnorrSignature<T>::ec2m_order;

template <typename T>
EC2E<T> SchnorrSignature<T>::ec2m_g;

template <typename T>
T SchnorrSignature<T>::ec2m_m;

template <typename T>
GF2E<T> SchnorrSignature<T>::ec2m_a;

template <typename T>
GF2E<T> SchnorrSignature<T>::ec2m_b;

template <typename T>
int SchnorrSignature<T>::ec2m_bits;

template <typename T>
T SchnorrSignature<T>::ecpk_sk;

template <typename T>
ECE<T> SchnorrSignature<T>::ecpk_pk;

template <typename T>
T SchnorrSignature<T>::ecpk_order;

template <typename T>
ECE<T> SchnorrSignature<T>::ecpk_g;

template <typename T>
T SchnorrSignature<T>::ecpk_p;

template <typename T>
Polynomial<GF<T>> SchnorrSignature<T>::ecpk_m;

template <typename T>
GFE<T> SchnorrSignature<T>::ecpk_a;

template <typename T>
GFE<T> SchnorrSignature<T>::ecpk_b;

template <typename T>
int SchnorrSignature<T>::ecpk_bits;

#endif // SCHNORR_SIGNATURE_H
