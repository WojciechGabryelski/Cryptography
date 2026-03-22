#ifndef EC2E_H
#define EC2E_H

#include "GF2E.h"
#include "NotInCurveException.h"
#include "UninitializedECException.h"

template <typename T>
class EC2E {
private:
    static GF2E<T> a;
    static GF2E<T> b;
    static bool initialized;
    GF2E<T> x;
    GF2E<T> y;
    bool inf;
public:
    static void init(GF2E<T> a, GF2E<T> b) {
        EC2E::a = a;
        EC2E::b = b;
        EC2E::initialized = true;
    }

    EC2E() {
        this->inf = true;
    }

    EC2E(GF2E<T> x, GF2E<T> y) {
        if (!EC2E::initialized) {
            throw UninitializedECException();
        }
        if (y * (y + x) != x * x * (x + EC2E::a) + EC2E::b) {
            throw NotInCurveException();
        }
        this->x = x;
        this->y = y;
        this->inf = false;
    }

    GF2E<T> getX() const {
        return this->x;
    }

    GF2E<T> getY() const {
        return this->y;
    }

    std::pair<GF2E<T>, GF2E<T>> getPoint() const {
        return {this->x, this->y};
    }

    EC2E operator - () const {
        if (this->inf) {
            return *this;
        }
        return EC2E(this->x, -this->y - this->x);
    }

    EC2E operator + (const EC2E &a) const {
        if (this->inf) {
            return a;
        }
        if (a.inf) {
            return *this;
        }
        if (a.x != this->x) {
            GF2E<T> lambda = (a.y + this->y) / (a.x + this->x);
            GF2E<T> new_x = lambda * lambda + lambda + EC2E::a + a.x + this->x;
            GF2E<T> new_y = lambda * (this->x + new_x) + new_x + this->y;
            return EC2E(new_x, new_y);
        }
        if (a.y == this->y) {
            return this->doublePoint();
        }
        return EC2E();
    }

    EC2E operator - (const EC2E &a) const {
        return *this + -a;
    }

    EC2E doublePoint() const {
        if (this->inf) {
            return *this;
        }
        GF2E<T> zero  = GF2E<T>((T) 0);
        if (this->x == zero) {
            return EC2E();
        }
        GF2E<T> lambda = this->x + this->y / this->x;
        GF2E<T> new_x = lambda * lambda + lambda + EC2E::a;
        GF2E<T> new_y = lambda * (this->x + new_x) + new_x + this->y;
        return EC2E(new_x, new_y);
    }

    EC2E operator * (T a) const {
        T zero = (T) 0;
        if (a < zero) {
            return (-*this) * (-a);
        }
        T one  = (T) 1;
        EC2E result = EC2E();
        EC2E b = *this;
        while (a != zero) {            
            if ((a & one) == one)
                result += b;
            b = b.doublePoint();
            a >>= 1;
        }
        return result;
    }

    bool operator == (const EC2E &a) const {
        return (this->inf && a.inf) || (!this->inf && !a.inf && this->x == a.x && this->y == a.y);
    }

    bool operator != (const EC2E &a) const {
        return (!this->inf || !a.inf) && (this->inf || a.inf || this->x != a.x || this->y != a.y);
    }

    friend std::ostream& operator << (std::ostream &s, const EC2E &a) {
        if (a.inf) {
            return s << "(inf)";
        }
        return s << "(" << a.x << ", " << a.y << ")";
    }

    EC2E operator += (const EC2E &a) {
        return *this = *this + a;
    }

    EC2E operator -= (const EC2E &a) {
        return *this = *this - a;
    }

    EC2E operator *= (T a) {
        return *this = *this * a;
    }
};

template <typename T>
GF2E<T> EC2E<T>::a;

template <typename T>
GF2E<T> EC2E<T>::b;

template <typename T>
bool EC2E<T>::initialized = false;

#endif // EC2E_H
