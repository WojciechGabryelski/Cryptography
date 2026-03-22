#ifndef ECE_H
#define ECE_H

#include "GFE.h"
#include "NotInCurveException.h"
#include "UninitializedECException.h"

template <typename T>
class ECE {
private:
    static GFE<T> a;
    static GFE<T> b;
    static bool initialized;
    GFE<T> x;
    GFE<T> y;
    bool inf;
public:
    static void init(GFE<T> a, GFE<T> b) {
        ECE::a = a;
        ECE::b = b;
        ECE::initialized = true;
    }

    ECE() {
        this->inf = true;
    }

    ECE(GFE<T> x, GFE<T> y) {
        if (!ECE::initialized) {
            throw UninitializedECException();
        }
        if (y * y != x * (x * x + ECE::a) + ECE::b) {
            throw NotInCurveException();
        }
        this->x = x;
        this->y = y;
        this->inf = false;
    }

    GFE<T> getX() const {
        return this->x;
    }

    GFE<T> getY() const {
        return this->y;
    }

    std::pair<GFE<T>, GFE<T>> getPoint() const {
        return {this->x, this->y};
    }

    ECE operator - () const {
        if (this->inf) {
            return *this;
        }
        return ECE(this->x, -this->y);
    }

    ECE operator + (const ECE &a) const {
        if (this->inf) {
            return a;
        }
        if (a.inf) {
            return *this;
        }
        if (a.x != this->x) {
            GFE<T> lambda = (a.y - this->y) / (a.x - this->x);
            GFE<T> new_x = lambda * lambda - a.x - this->x;
            GFE<T> new_y = lambda * (this->x - new_x) - this->y;
            return ECE(new_x, new_y);
        }
        if (a.y == this->y) {
            return this->doublePoint();
        }
        return ECE();
    }

    ECE operator - (const ECE &a) const {
        return *this + -a;
    }

    ECE doublePoint() const {
        if (this->inf) {
            return *this;
        }
        GFE<T> zero  = GFE<T>(Polynomial<GF<T>>(std::vector<GF<T>>({})));
        GFE<T> two   = GFE<T>(Polynomial<GF<T>>(std::vector<GF<T>>({(T) 2})));
        GFE<T> three = GFE<T>(Polynomial<GF<T>>(std::vector<GF<T>>({(T) 3})));
        if (this->y == zero) {
            return ECE();
        }
        GFE<T> lambda = (three * this->x * this->x + ECE::a) / (two * this->y);
        GFE<T> new_x = lambda * lambda - two * this->x;
        GFE<T> new_y = lambda * (this->x - new_x) - this->y;
        return ECE(new_x, new_y);
    }

    ECE operator * (T a) const {
        T zero = (T) 0;
        if (a < zero) {
            return (-*this) * (-a);
        }
        T one  = (T) 1;
        ECE result = ECE();
        ECE b = *this;
        while (a != zero) {
            if ((a & one) == one)
                result += b;
            b = b.doublePoint();
            a >>= 1;
        }
        return result;
    }

    bool operator == (const ECE &a) const {
        return (this->inf && a.inf) || (!this->inf && !a.inf && this->x == a.x && this->y == a.y);
    }

    bool operator != (const ECE &a) const {
        return (!this->inf || !a.inf) && (this->inf || a.inf || this->x != a.x || this->y != a.y);
    }

    friend std::ostream& operator << (std::ostream &s, const ECE &a) {
        if (a.inf) {
            return s << "(inf)";
        }
        return s << "(" << a.x << ", " << a.y << ")";
    }

    ECE operator += (const ECE &a) {
        return *this = *this + a;
    }

    ECE operator -= (const ECE &a) {
        return *this = *this - a;
    }

    ECE operator *= (T a) {
        return *this = *this * a;
    }
};

template <typename T>
GFE<T> ECE<T>::a;

template <typename T>
GFE<T> ECE<T>::b;

template <typename T>
bool ECE<T>::initialized = false;

#endif // ECE_H
