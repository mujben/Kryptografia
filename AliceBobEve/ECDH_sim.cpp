    #include "ECDH.h"
    #include "CryptoHelper.cpp"
    #include "ECHelper.h"
    #include "Simulation.cpp"

    using namespace std;

    struct ECDH_sim : Simulation {
        ECDH_sim() {
            simulation_name = "ECDH man-in-the-middle simulation";
            run();
        }

        void alice() override {
            ECDH Alice = ECDH(curve, g, n);
            Point alice_public_key = Alice.get_public_key();
            Point bob_public_key = {curve};
            Point shared_secret = {curve};

            semAlice.acquire();
            {
                mailbox = {Sender::Alice, string(alice_public_key)};
                cout << "Alice sends to Bob: \n" << mailbox << "\n";
                getchar();
            }
            semEve.release();

            semAlice.acquire();
            {
                cout << "Alice receives: \n" << mailbox;

                cout << "Alice saves this as Bob's public key and calculates a shared secret\n\n";
                bob_public_key = Point(mailbox.text, curve);
                shared_secret = Alice.calculate_shared_secret(bob_public_key);

                mailbox = {Sender::Alice, encrypt("I love you Bob", shared_secret)};
                cout << "Alice sends to Bob: \n" << mailbox << "\n";
                getchar();
            }
            semEve.release();

            semAlice.acquire();
            {
                cout << "Alice receives: \n" << mailbox;

                cout << "Alice decrypts what she thinks is a message from Bob and gets: \n";
                string message = decrypt(mailbox.text, shared_secret);
                cout << message << "\n";
                cout << "Alice is heartbroken.\n\n";

                cout << "DON'T LET THAT HAPPEN TO YOU\n";
                cout << "USE AUTHENTICATION\n";
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

                cout << "Eve saves this as Alice's public key\n\n";
                alice_public_key = Point(mailbox.text, curve);
                alice_shared_point = Eve.calculate_shared_secret(alice_public_key);

                mailbox.text = string(eve_public_key);
                cout << "Eve sends to Bob: \n" << mailbox << "\n";
                getchar();
            }
            semBob.release();

            semEve.acquire();
            {
                cout << "Eve intercepts: \n" << mailbox;

                cout << "Eve saves this as Bob's public key and calculates a shared secret\n\n";
                bob_public_key = Point(mailbox.text, curve);
                bob_shared_point = Eve.calculate_shared_secret(bob_public_key);

                mailbox.text = string(eve_public_key);
                cout << "Eve sends to Alice: \n" << mailbox << "\n";
                getchar();
            }
            semAlice.release();

            semEve.acquire();
            {
                cout << "Eve intercepts: \n" << mailbox;

                cout << "Alice encrypted this message using Eve's public key so Eve can now decrypt it and gets: \n";
                string message = decrypt(mailbox.text, alice_shared_point);
                cout << message << "\n";
                cout << "Eve chooses not to change it and encrypts it with Bob's public key so he can decrypt it\n\n";

                mailbox.text = string(encrypt(message, bob_shared_point));
                cout << "Eve sends to Bob: \n" << mailbox << "\n";
                getchar();
            }
            semBob.release();

            semEve.acquire();
            {
                cout << "Eve intercepts: \n" << mailbox;

                cout << "She decrypts and gets: \n";
                string message = decrypt(mailbox.text, bob_shared_point);
                cout << message << "\n";
                cout << "Eve can't stand that! She changes the message...\n\n";
                message = "I HATE you, Alice!";

                mailbox.text = string(encrypt(message, alice_shared_point));
                cout << "Eve sends to Alice: \n" << mailbox << "\n";
                getchar();
            }
            semAlice.release();
        }

        void bob() override {
            ECDH Bob = ECDH(curve, g, n);
            Point bob_public_key = Bob.get_public_key();
            Point alice_public_key = {curve};
            Point alice_shared_point = {curve};

            semBob.acquire();
            {
                cout << "Bob receives: \n" << mailbox;

                cout << "Bob saves this as Alice's public key and calculates a shared secret\n\n";
                alice_public_key = Point(mailbox.text, curve);
                alice_shared_point = Bob.calculate_shared_secret(alice_public_key);

                mailbox = {Sender::Bob, string(bob_public_key)};
                cout << "Bob sends to Alice: \n" << mailbox << "\n";
                getchar();
            }
            semEve.release();

            semBob.acquire();
            {
                cout << "Bob receives: \n" << mailbox;

                cout << "Bob decrypts it and gets: \n";
                string message = decrypt(mailbox.text, alice_shared_point);
                cout << message << "\n";
                cout << "He is so happy now and he sends his encrypted response\n\n";

                mailbox = {Sender::Bob, encrypt("I love you too Alice!", alice_shared_point)};
                cout << "Bob sends to Alice: \n" << mailbox << "\n";
                getchar();
            }
            semEve.release();
        }
    };

    int main() {
        if (sodium_init() < 0) return 1;
        ECDH_sim sim;

        return 0;
    }