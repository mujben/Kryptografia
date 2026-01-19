#include <sstream>
#include "Simulation.cpp"
#include "CryptoHelper.cpp"
#include "ECDSA.h"
#include "ECDH.h"

struct ECDSA_sim : Simulation {
    Point ECDSA_alice_public_key = {curve};
    Point ECDSA_bob_public_key = {curve};

    ECDSA_sim() {
        simulation_name = "ECDSA failed man-in-the-middle simulation";
        cout << boolalpha;
        run();
    }

    void alice() override {
        ECDSA AliceDSA = ECDSA(curve, g, n);

        semAlice.acquire();
        {
            cout << "Alice makes her public ECDSA key available..\n\n";
            ECDSA_alice_public_key = AliceDSA.get_public_key();
            getchar();
        }
        semBob.release();

        ECDH Alice = ECDH(curve, g, n);
        Point alice_public_key = Alice.get_public_key();
        Point bob_public_key = {curve};
        Point shared_point = {curve};

        semAlice.acquire();
        {
            string message = string(alice_public_key);
            Signature signature = AliceDSA.sign(message);
            mailbox = {Sender::Alice, string(alice_public_key) + " " + string(signature)};
            cout << "Alice sends to Bob: \n" << mailbox << "\n";
            getchar();
        }
        semEve.release();

        semAlice.acquire();
        {
            cout << "Alice tries one more time...\n\n";
            string message = string(alice_public_key);
            Signature signature = AliceDSA.sign(message);
            mailbox = {Sender::Alice, string(alice_public_key) + " " + string(signature)};
            cout << "Alice sends to Bob: \n" << mailbox << "\n";
            getchar();
        }
        semBob.release();

        semAlice.acquire();
        {
            cout << "Alice receives: \n" << mailbox;
            cout << "Alice tries to verify the signature of the message with result: ";
            LL a, b, c, d;
            istringstream iss(mailbox.text);
            iss >> a >> b >> c >> d;
            cout << AliceDSA.verify(to_string(a) + " " + to_string(b), {{c, n}, {d, n}}, ECDSA_bob_public_key, curve, g, n) << "\n";
            bob_public_key = Point({a, curve.p}, {b, curve.p}, false, curve);
            shared_point = Alice.calculate_shared_secret(bob_public_key);

            cout << "Alice can now safely send message to Bob\n\n";
            string message = "I'm so happy we got rid of Eve! Wanna go see a movie tomorrow?";
            string encrypted = encrypt(message, shared_point);
            Signature signature = AliceDSA.sign(encrypted);
            mailbox = {Sender::Alice, encrypted + " " + string(signature)};
            cout << "Alice sends to Bob: \n" << mailbox << "\n";
            getchar();
        }
        semBob.release();

        semAlice.acquire();
        {
            cout << "Alice receives: \n" << mailbox;
            cout << "Alice tries to verify the signature of the message with result: ";
            string encrypted_message;
            LL c, d;
            istringstream iss(mailbox.text);
            iss >> encrypted_message >> c >> d;
            cout << AliceDSA.verify(encrypted_message, {{c, n}, {d, n}}, ECDSA_bob_public_key, curve, g, n) << "\n";
            cout << "Alice can now decrypt: \n";
            cout << decrypt(encrypted_message, shared_point);

            cout << "\n\nSEE?? IT'S NOT THAT HARD\n";
            cout << "JUST AUTHENTICATE\n";
            getchar();
        }
    }

    void eve() override {
        ECDH Eve = ECDH(curve, g, n);
        Point eve_public_key = Eve.get_public_key();
        Point alice_public_key = {curve};
        Point alice_shared_point = {curve};
        Point bob_public_key = {curve};
        Point bob_shared_point = {curve};

        semEve.acquire();
        {
            cout << "Eve intercepts: \n" << mailbox;
            cout << "Eve saves Alice's public key\n";

            LL a, b, c, d;
            istringstream iss(mailbox.text);
            iss >> a >> b >> c >> d;

            alice_public_key = Point({a, curve.p}, {b, curve.p}, false, curve);
            alice_shared_point = Eve.calculate_shared_secret(alice_public_key);

            cout << "Eve tries to send her public key instead\n\n";
            mailbox.text = string(eve_public_key) + " " +  to_string(c) + " " + to_string(d);
            cout << "Eve sends to Bob: \n" << mailbox << "\n";
            getchar();
        }
        semBob.release();

        semEve.acquire();
        {
            cout << "Eve can also try to sign her public key\n\n";
            ECDSA EveDSA = ECDSA(curve, g, n);
            Signature signature = EveDSA.sign(string(eve_public_key));
            mailbox.text = string(eve_public_key) + " " + string(signature);
            cout << "Eve sends to Bob: \n" << mailbox << "\n";
            getchar();
        }
        semBob.release();
    }

    void bob() override {
        ECDSA BobDSA = ECDSA(curve, g, n);

        semBob.acquire(); 
        {
            cout << "Bob makes his public ECDSA key available..\n\n";
            ECDSA_bob_public_key = BobDSA.get_public_key();
            getchar();
        }
        semAlice.release();


        ECDH Bob = ECDH(curve, g, n);
        Point bob_public_key = Bob.get_public_key();
        Point alice_public_key = {curve};
        Point shared_point = {curve};

        semBob.acquire();
        {
            cout << "Bob receives: \n" << mailbox;
            cout << "Bob tries to verify the signature of the message with result: ";
            LL a, b, c, d;
            istringstream iss(mailbox.text);
            iss >> a >> b >> c >> d;
            cout << BobDSA.verify(to_string(a) + " " + to_string(b), {{c, n}, {d, n}}, ECDSA_alice_public_key, curve, g, n) << "\n\n";
            getchar();
        }
        semEve.release();

        semBob.acquire();
        {
            cout << "Bob receives: \n" << mailbox;
            cout << "Bob tries to verify the signature of the message with result: ";
            LL a, b, c, d;
            istringstream iss(mailbox.text);
            iss >> a >> b >> c >> d;
            cout << BobDSA.verify(to_string(a) + " " + to_string(b), {{c, n}, {d, n}}, ECDSA_alice_public_key, curve, g, n) << "\n\n";
            getchar();
        }
        semAlice.release();

        semBob.acquire();
        {
            cout << "Without Eve, Bob receives: \n" << mailbox;
            cout << "Bob tries to verify the signature of the message with result: ";
            LL a, b, c, d;
            istringstream iss(mailbox.text);
            iss >> a >> b >> c >> d;
            cout << BobDSA.verify(to_string(a) + " " + to_string(b), {{c, n}, {d, n}}, ECDSA_alice_public_key, curve, g, n) << "\n";
            cout << "Bob saves Alice's public key for this session and sends his own\n\n";
            alice_public_key = Point({a, curve.p}, {b, curve.p}, false, curve);
            shared_point = Bob.calculate_shared_secret(alice_public_key);

            Signature signature = BobDSA.sign(string(bob_public_key));
            mailbox = {Sender::Bob, string(bob_public_key) + " " + string(signature)};
            cout << "Bob sends to Alice: \n" << mailbox << "\n";
            getchar();
        }
        semAlice.release();

        semBob.acquire();
        {
            cout << "Bob receives: \n" << mailbox;
            string encrypted_message;
            LL c, d;
            istringstream iss(mailbox.text);
            iss >> encrypted_message >> c >> d;

            cout << "Bob tries to verify the signature of the message with result: ";
            cout << BobDSA.verify(encrypted_message, {{c, n}, {d, n}}, ECDSA_alice_public_key, curve, g, n) << "\n";

            cout << "Bob can now decrypt the message: \n";
            string decrypted = decrypt(encrypted_message, shared_point);
            cout << decrypted << "\n\n";

            string message = "Sure!";
            encrypted_message = encrypt(message, shared_point);

            Signature signature = BobDSA.sign(encrypted_message);

            mailbox = {Sender::Bob, encrypted_message + " " + string(signature)};
            cout << "Bob sends to Alice: \n" << mailbox << "\n";
            getchar();
        }
        semAlice.release();
    }
};

int main() {
    if (sodium_init() < 0) return 1;
    ECDSA_sim sim;

    return 0;
}