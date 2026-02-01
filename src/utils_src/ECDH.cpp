#include "ECDH.h"
#include "MathHelper.h"
#include "Int.h"

ECDH::ECDH(const EC& curve, const Point& G, const LL n)
    : curve(curve), G(G), n(n), public_key(curve) {
    if (!(n*G).inf || G.curve != curve) throw runtime_error("Invalid generator point");
    this->private_key = random_LL(1, n - 1);
    this->public_key = this->private_key * this->G;
}

Point ECDH::get_public_key() const {
    return this->public_key;
}

Point ECDH::calculate_shared_secret(const Point& other_public_key) const {
    if (this->curve != other_public_key.curve) {
        throw runtime_error("Curve mismatch in ECDH secret calculation");
    }
    if (other_public_key.inf == true) {
        throw runtime_error("Foreign public key is the point at infinity");
    }
    const Int a_mod(this->curve.a, this->curve.p);
    const Int b_mod(this->curve.b, this->curve.p);
    const Int lhs = other_public_key.y.pow(2);
    const Int rhs = other_public_key.x.pow(3) + a_mod * other_public_key.x + b_mod;
    if (lhs != rhs) {
        throw runtime_error("Foreign public key is not on the curve");
    }
    return this->private_key * other_public_key;
}
