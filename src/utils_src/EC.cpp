#include <random>
#include "Int.h"
#include "MathHelper.h"
#include "EC.h"

void EC::init_random(LL modulo) {
    this->p = modulo;
    this->a = Int(0, modulo);
    this->b = Int(0, modulo);

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<LL> dis(1, modulo - 1);

    Int delta(0, p);
    do {
        a = Int(dis(gen), p);
        b = Int(dis(gen), p);
        delta = Int(4, p) * a * a * a + Int(27, p) * b * b;
    } while (delta == Int(0, p));
}

EC::EC(LL a_val, LL b_val, LL modulo)
    : a(a_val, modulo), b(b_val, modulo), p(modulo)
{
    if (!is_prime(p)) throw runtime_error("Invalid modulus: p must be a prime number.");
    Int delta = Int(4, p) * a * a * a + Int(27, p) * b * b;
    if (delta == Int(0, p)) {
        throw runtime_error("Invalid curve (delta is zero)");
    }
}

EC::EC(const LL modulo) {
    if (!is_prime(modulo)) throw runtime_error("Invalid modulus: p must be a prime number.");
    init_random(modulo);
}

EC::EC() {
    init_random(65537);
}

bool EC::operator==(const EC& rhs) const {
    return this->a == rhs.a && this->b == rhs.b;
}

bool EC::operator!=(const EC& rhs) const {
    return !(*this == rhs);
}

std::ostream& operator<<(std::ostream& os, const EC& curve) {
    os << "----- Curve -----\n";
    os << "a: " << curve.a << ", b: " << curve.b << "\n";
    return os;
}
