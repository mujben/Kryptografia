//efficiency simulation between naive point counting algorithm and Shank's Baby Step Giant Step solution.
#include <iostream>
#include <fstream>
#include <chrono>
#include <filesystem>
#include <map>
#include <iomanip>
#include "ECHelper.h"
#include "MathHelper.h"
using namespace std;

static const std::map<int, LL> primes = {
    {3, 7},
    {4, 13},
    {5, 31},
    {6, 61},
    {7, 127},
    {8, 251},
    {9, 509},
    {10, 1021},
    {11, 2039},
    {12, 4093},
    {13, 8191},
    {14, 16381},
    {15, 32749},
    {16, 65521},
    {17, 131071},
    {18, 262139},
    {19, 524287},
    {20, 1048573},
    {21, 2097143},
    {22, 4194301},
    {23, 8388593},
    {24, 16777213},
    {25, 33554393},
    {26, 67108859},
    {27, 134217689},
    {28, 268435399},
    {29, 536870909},
    {30, 1073741789},
    {31, 2147483647},
    {32, 4294967291},
    {33, 8589934583},
    {34, 17179869143},
    {35, 34359738337},
    {36, 68719476731},
    {37, 137438953447},
    {38, 274877906899},
    {39, 549755813881},
    {40, 1099511627689},
    {41, 2199023255531},
    {42, 4398046511093},
    {43, 8796093022151},
    {44, 17592186044399},
    {45, 35184372088777},
    {46, 70368744177643},
    {47, 140737488355213},
    {48, 281474976710597},
    {49, 562949953421231},
    {50, 1125899906842597},
    {51, 2251799813685119},
    {52, 4503599627370449},
    {53, 9007199254740881},
    {54, 18014398509481951},
    {55, 36028797018963913},
    {56, 72057594037927931},
    {57, 144115188075855859},
    {58, 288230376151711717},
    {59, 576460752303423433},
    {60, 1152921504606846883},
    {61, 2305843009213693951},
    {62, 4611686018427387847}
};

tuple<int, double, double> measure_time(const int bit_len, const int ITERATIONS = 1000, const int MAX_NAIVE = 16) {
    double total_duration_bsgs = 0.0;
    double total_duration_naive = 0.0;

    for (int i = 0; i < ITERATIONS; i++) {
        const LL p = primes.at(bit_len);
        EC curve(p);

        chrono::time_point<chrono::high_resolution_clock> start_bsgs = chrono::high_resolution_clock::now();
        const LL order_bsgs = find_order_bsgs(curve);
        chrono::time_point<chrono::high_resolution_clock> end_bsgs = chrono::high_resolution_clock::now();

        double duration_bsgs = chrono::duration<double, milli>(end_bsgs - start_bsgs).count();
        total_duration_bsgs += duration_bsgs;

        if (bit_len <= MAX_NAIVE) {
            chrono::time_point<chrono::high_resolution_clock> start_naive = chrono::high_resolution_clock::now();
            const LL order_naive = find_order(curve);
            chrono::time_point<chrono::high_resolution_clock> end_naive = chrono::high_resolution_clock::now();

            double duration_naive = chrono::duration<double, milli>(end_naive - start_naive).count();
            total_duration_naive += duration_naive;

            // if (order_bsgs != order_naive && order_naive != -1) {
            //     throw runtime_error("Orders don't match");
            // }
        }
    }
    double avg_bsgs = total_duration_bsgs / static_cast<float>(ITERATIONS);
    double avg_naive = (bit_len <= MAX_NAIVE) ? (total_duration_naive / static_cast<float>(ITERATIONS)) : -1.0;
    cout << "finished bits: " << bit_len << ", bsgs: " << avg_bsgs << ", naive: " << avg_naive << endl;
    return {bit_len, avg_bsgs, avg_naive};
}


int main() {
    if (filesystem::exists("benchmark.csv")) {
        if (remove("benchmark.csv") != 0) {
            cout << "Error removing 'benchmark.csv'.\n";
            return -1;
        }
    }
    ofstream benchmark("benchmark.csv");
    benchmark << "bits,bsgs_ms,naive_ms\n";
    for (int i = 3; i <= 62; i++) {
        try {
            tuple <int, double, double> data = measure_time(i);
            benchmark << fixed << setprecision(6) << get<0>(data) << "," << get<1>(data) << "," << get<2>(data) << "\n" << flush;
        } catch (const exception &e) {
            cerr << "Can't measure time for bit length: " << i << ", error: " << e.what() << endl;
        }
    }
}