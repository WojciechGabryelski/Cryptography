#ifndef EC_H
#define EC_H

#include "GF.h"
#include "NotInCurveException.h"
#include "UninitializedECException.h"

template <typename T>
class EC {
private:
    static GF<T> a;
    static GF<T> b;
    static bool initialized;
    GF<T> x;
    GF<T> y;
    bool inf;
public:
    static void init(GF<T> a, GF<T> b) {
        EC::a = a;
        EC::b = b;
        EC::initialized = true;
    }

    EC() {
        this->inf = true;
    }

    EC(GF<T> x, GF<T> y) {
        if (!EC::initialized) {
            throw UninitializedECException();
        }
        if (y * y != x * (x * x + EC::a) + EC::b) {
            throw NotInCurveException();
        }
        this->x = x;
        this->y = y;
        this->inf = false;
    }

    GF<T> getX() const {
        return this->x;
    }

    GF<T> getY() const {
        return this->y;
    }

    std::pair<GF<T>, GF<T>> getPoint() const {
        return {this->x, this->y};
    }

    EC operator - () const {
        if (this->inf) {
            return *this;
        }
        return EC(this->x, -this->y);
    }

    EC operator + (const EC &a) const {
        if (this->inf) {
            return a;
        }
        if (a.inf) {
            return *this;
        }
        if (a.x != this->x) {
            GF<T> lambda = (a.y - this->y) / (a.x - this->x);
            GF<T> new_x = lambda * lambda - a.x - this->x;
            GF<T> new_y = lambda * (this->x - new_x) - this->y;
            return EC(new_x, new_y);
        }
        if (a.y == this->y) {
            return this->doublePoint();
        }
        return EC();
    }

    EC operator - (const EC &a) const {
        return *this + -a;
    }

    EC doublePoint() const {
        if (this->inf) {
            return *this;
        }
        GF<T> zero  = GF<T>((T) 0);
        GF<T> two   = GF<T>((T) 2);
        GF<T> three = GF<T>((T) 3);
        if (this->y == zero) {
            return EC();
        }
        GF<T> lambda = (three * this->x * this->x + EC::a) / (two * this->y);
        GF<T> new_x = lambda * lambda - two * this->x;
        GF<T> new_y = lambda * (this->x - new_x) - this->y;
        return EC(new_x, new_y);
    }

    EC operator * (T a) const {
        T zero = (T) 0;
        if (a < zero) {
            return (-*this) * (-a);
        }
        T one  = (T) 1;
        EC result = EC();
        EC b = *this;
        while (a != zero) {
            if ((a & one) == one)
                result += b;
            b = b.doublePoint();
            a >>= 1;
        }
        return result;
    }

    bool operator == (const EC &a) const {
        return (this->inf && a.inf) || (!this->inf && !a.inf && this->x == a.x && this->y == a.y);
    }

    bool operator != (const EC &a) const {
        return (!this->inf || !a.inf) && (this->inf || a.inf || this->x != a.x || this->y != a.y);
    }

    friend std::ostream& operator << (std::ostream &s, const EC &a) {
        if (a.inf) {
            return s << "(inf)";
        }
        return s << "(" << a.x << ", " << a.y << ")";
    }

    EC operator += (const EC &a) {
        return *this = *this + a;
    }

    EC operator -= (const EC &a) {
        return *this = *this - a;
    }

    EC operator *= (T a) {
        return *this = *this * a;
    }
};

template <typename T>
GF<T> EC<T>::a;

template <typename T>
GF<T> EC<T>::b;

template <typename T>
bool EC<T>::initialized = false;

#endif // EC_H
