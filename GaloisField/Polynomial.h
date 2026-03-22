#ifndef POLYNOMIAL_H
#define POLYNOMIAL_H

#include <iostream>
#include <vector>
#include "ZeroInversionException.h"

template <typename T>
class Polynomial {
private:
    std::vector<T> coef;

    void division(const Polynomial &a, std::vector<T> &quotient, std::vector<T> &reminder) const {
        uint64_t n = this->coef.size();
        uint64_t m = a.coef.size();
        if (m == 1 && a.coef[0] == (T) 0)
            throw ZeroInversionException();
        reminder = this->coef;
        if (m > n) {
            quotient = std::vector<T>(1, (T) 0);
            return;
        }
        quotient = std::vector<T>(n - m + 1);
        for (int64_t i = n - 1; i >= (int64_t) m - 1; --i) {
            T b = reminder[i] / (a.coef)[m - 1];
            quotient[i - m + 1] = b;
            for (uint64_t j = 1; j < m; ++j) {
                reminder[i - j] -= b * (a.coef)[m - j - 1];
            }
            reminder.pop_back();
        }
    }
public:
    Polynomial() = default;

    Polynomial(const std::vector<T>& coef) {
        this->setCoefficients(coef);
    }

    std::vector<T> getCoefficients() {
        return this->coef;
    }

    void setCoefficients(const std::vector<T>& coef) {
        this->coef = coef;
        while (!this->coef.empty() && this->coef.back() == (T) 0) {
            this->coef.pop_back();
        }
    }

    void setCoefficient(unsigned int i, T a) {
        if (i < coef.size()) {
            if (i == coef.size() - 1 && a == (T) 0) {
                coef.pop_back();
            } else {
                coef[i] = a;
            }
        }
    }

    int64_t degree() const {
        return this->coef.size() - 1;
    }

    Polynomial operator = (T b) {
        return *this = Polynomial({b});
    }

    Polynomial operator - () const {
        std::vector<T> v(this->coef.size());
        for (uint64_t i = 0; i < this->coef.size(); ++i) {
            v[i] = -this->coef[i];
        }
        return Polynomial(v);
    }

    Polynomial operator + (const Polynomial &a) const {
        uint64_t n = this->coef.size();
        uint64_t m = a.coef.size();
        std::vector<T> v(std::max(n, m));
        if (n < m) {
            std::swap(n, m);
            for (uint64_t i = m; i < n; ++i)
                v[i] = a.coef[i];
        } else {
            for (uint64_t i = m; i < n; ++i)
                v[i] = this->coef[i];
        }

        for (uint64_t i = 0; i < m; ++i) {
            v[i] = this->coef[i] + a.coef[i];
        }
        return Polynomial(v);
    }

    Polynomial operator - (const Polynomial &a) const {
        uint64_t n = this->coef.size();
        uint64_t m = a.coef.size();
        std::vector<T> v(std::max(n, m));
        if (n < m) {
            std::swap(n, m);
            for (uint64_t i = m; i < n; ++i)
                v[i] = -a.coef[i];
        } else {
            for (uint64_t i = m; i < n; ++i)
                v[i] = this->coef[i];
        }

        for (uint64_t i = 0; i < m; ++i) {
            v[i] = this->coef[i] - a.coef[i];
        }
        return Polynomial(v);
    }

    Polynomial operator * (const Polynomial &a) const {
        uint64_t n = this->coef.size();
        uint64_t m = a.coef.size();
        if (n == 0 || m == 0) {
            return Polynomial(std::vector<T>({(T) 0}));
        }
        std::vector<T> v(m + n - 1);
        for (uint64_t i = 0; i < m + n - 1; ++i) {
            v[i] = 0;
        }
        for (uint64_t i = 0; i < n; ++i) {
            for (uint64_t j = 0; j < m; ++j) {
                v[i + j] += this->coef[i] * a.coef[j];
            }
        }
        return Polynomial(v);
    }

    Polynomial operator / (const Polynomial &a) const {
        std::vector<T> quotient;
        std::vector<T> reminder;
        division(a, quotient, reminder);
        return Polynomial(quotient);
    }

    Polynomial operator % (const Polynomial &a) const {
        std::vector<T> quotient;
        std::vector<T> reminder;
        division(a, quotient, reminder);
        return Polynomial(reminder);
    }

    static Polynomial gcd(Polynomial a, Polynomial b) {
        Polynomial zero = Polynomial(std::vector<T>({(T) 0}));
        while (b != zero) {
            a %= b;
            Polynomial c = a;
            a = b;
            b = c;
        }
        return a;
    }

    T operator () (T x) {
        T result = (T) 0;
        for (int64_t i = this->coef.size() - 1; i >= 0; --i) {
            result *= x;
            result += this->coef[i];
        }
        return result;
    }

    T operator [] (unsigned int n) {
        if (n > this->coef.size())
            return 0;
        return this->coef[n];
    }

    bool operator == (const Polynomial &a) const {
        if ((this->coef).size() != a.coef.size())
            return false;
        for (uint64_t i = 0; i < a.coef.size(); i++) {
            if (this->coef[i] != a.coef[i])
                return false;
        }
        return true;
    }

    bool operator != (const Polynomial &a) const {
        return !(*this == a);
    }

    Polynomial operator += (const Polynomial &a) {
        return *this = *this + a;
    }

    Polynomial operator -= (const Polynomial &a) {
        return *this = *this - a;
    }

    Polynomial operator *= (const Polynomial &a) {
        return *this = *this * a;
    }

    Polynomial operator /= (const Polynomial &a) {
        return *this = *this / a;
    }

    Polynomial operator %= (const Polynomial &a) {
        return *this = *this % a;
    }

    friend std::ostream& operator << (std::ostream &s, const Polynomial &a) {
        T zero = (T) 0;
        T one = (T) 1;
        if (a.coef.size() > 0) {
            if (a.coef[0] != zero) {
                s << a.coef[0];
            }
            if (a.coef.size() > 1) {
                if (a.coef[0] != zero) {
                    s << "+";
                }
                if (a.coef[1] != zero) {
                    if (a.coef[1] != one) {
                        s << a.coef[1] << "*";
                    }
                    s << "x";
                }
                if (a.coef.size() > 2) {
                    if (a.coef[1] != zero) {
                        s << "+";
                    }
                    for (uint64_t i = 2; i < a.coef.size() - 1; ++i) {
                        if (a.coef[i] != zero) {
                            if (a.coef[i] != one) {
                                s << a.coef[i] << "*";
                            }
                            s << "x^" << i << "+";
                        }
                    }
                    if (a.coef.back() != one) {
                        s << a.coef.back() << "*";
                    }
                    s << "x^" << a.coef.size() - 1;
                }
            }
            return s;
        }
        return s << zero;
    }
};

#endif // POLYNOMIAL_H
