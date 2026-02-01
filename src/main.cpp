#include <iostream>
#include <array>
#include <chrono>
#include "EC.h"
#include "ECHelper.h"
#include "Int.h"
#include "Point.h"
#include "MathHelper.h"
#include "ECDH.h"
#include "ECDSA.h"

using namespace std;

int main() {
    constexpr LL p = 4611686018427387847; //62-bit prime
    EC curve(p);
    LL curve_order = 0;
    array<LL, 2> factored{};

    int tries = 1;
    chrono::steady_clock::time_point curve_begin = chrono::steady_clock::now();
    while (factored[0] == 0) {
        cout << "\r" << tries << flush;
        curve = EC(p);
        curve_order = find_order_bsgs(curve);
        factored = factor(curve_order);
        tries++;
    }
    chrono::steady_clock::time_point curve_end = chrono::steady_clock::now();

    chrono::steady_clock::time_point generator_begin = chrono::steady_clock::now();
    const Point g = find_generator(curve, factored);
    chrono::steady_clock::time_point generator_end = chrono::steady_clock::now();

    cout << curve << "\n";
    cout << "This curve has an order of: " << curve_order << " = h * n\n";
    cout << "h: " << factored[0] << "\nn: " << factored[1] << "\n";
    cout << "Time taken to choose a good curve: " << chrono::duration_cast<chrono::milliseconds>(curve_end - curve_begin).count() << " milliseconds " << "(in " << tries << " tries)\n";
    cout << "Generator point chosen: (" << g.x << ", " << g.y << ")\n";
    cout << "Time taken to choose generator: " << chrono::duration_cast<chrono::microseconds>(generator_end - generator_begin).count() << " microseconds\n";


    LL n = factored[1];

    cout << "\n--- ECDH protocol ---\n";
    ECDH Alice(curve, g, n);
    Point QA = Alice.get_public_key();
    cout << "Alice's public key (QA): (" << QA.x << ", " << QA.y << ")\n";

    ECDH Bob(curve, g, n);
    Point QB = Bob.get_public_key();
    cout << "Bob's public key (QB): (" << QB.x << ", " << QB.y << ")\n";

    Point shared_A = Alice.calculate_shared_secret(QB);
    Point shared_B = Bob.calculate_shared_secret(QA);

    cout << "\n--- Shared secret calculation ---\n";
    cout << "Alice's calculated secret: (" << shared_A.x << ", " << shared_A.y << ")\n";
    cout << "Bob's calulated secret: (" << shared_B.x << ", " << shared_B.y << ")\n";

    if (shared_A == shared_B && !shared_A.inf) {
        cout << "\nSuccess: Shared secrets match. \n";
    } else {
        cout << "\nShared secrets do not match OR are point at infinity. \n";
    }

    cout << "\n--- ECDSA protocol ---\n";

    ECDSA alice(curve, g, n);
    Point Qa = alice.get_public_key();
    cout << "Alice's Public Key (QA): (" << Qa.x << ", " << Qa.y << ")\n";

    string message = "Message to sign";
    cout << "Message: \"" << message << "\"\n";

    Signature sig = alice.sign(message);
    cout << "Signature (r, s): (" << sig.r << "," << sig.s << ")\n";

    bool is_valid = ECDSA::verify(message, sig, Qa, curve, g, n);

    if (is_valid) {
        cout << "\nSuccess: Signature valid. \n";
    } else {
        cout << "\nFailure: Signature is not valid. \n";
    }

    return 0;
}
