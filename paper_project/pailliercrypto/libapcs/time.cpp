#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

#include <string.h>
#include <ctype.h>
#include <iostream>

#include <libhcs.h>
#include <gmpxx.h>
#include <chrono>
#include "../libhcs/test/catch.hpp"
#include "../libhcs/include/libhcs++/pcs.hpp"
#include "libapcs.h"
using namespace std;

static hcs::random *hr;
static hcs::pcs::public_key *pk;
static hcs::pcs::private_key *vk;

int main(void)
{
    cout << '\n';
    chrono::high_resolution_clock::time_point time_start;
    chrono::high_resolution_clock::time_point time_end;

    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();
    hcs_random *hr = hcs_init_random();

    pcs_generate_key_pair(pk, vk, hr, 2048);

    mpz_t a, b, c_add, c_mul, add_result, sub_result, left_shift_result, right_shift_result;
    mpz_t enc_a, enc_b, add_c, mul_c, result_a, result_m;

    mpz_inits(a, b, c_add, c_mul, enc_a, enc_b, add_c, mul_c, result_a, result_m, add_result, sub_result, left_shift_result, right_shift_result, NULL);

    unsigned int k;

    cout << "input a and b and k: ";
    cin >> a >> b >> k;
    cout << '\n';

    //Plain add
    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000000; i++)
    {
        mpz_add(result_a, a, b);
    }
    time_end = chrono::high_resolution_clock::now();
    auto time_diff_padd = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Plain add Time = [" << time_diff_padd.count() << " microseconds] " << endl;

    //Plain multi
    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000000; i++)
    {
        mpz_mul(result_m, a, b);
    }
    time_end = chrono::high_resolution_clock::now();
    auto time_diff_pmul = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Plain mul Time = [" << time_diff_pmul.count() << " microseconds] " << endl;

    // Make a Encryption
    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; i++)
    {
        pcs_encrypt(pk, hr, enc_a, a);
    }
    time_end = chrono::high_resolution_clock::now();
    auto time_diff_enca = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Enc a Time = [" << time_diff_enca.count() / 100 << " microseconds] " << endl;

    // Make b Encryption
    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; i++)
    {
        pcs_encrypt(pk, hr, enc_b, b);
    }
    time_end = chrono::high_resolution_clock::now();
    auto time_diff_encb = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Enc b Time = [" << time_diff_encb.count() / 100 << " microseconds] " << endl;

    // Cal Enc(a) + Enc(b)
    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < (10000); i++)
    {
        pcs_ee_add(pk, add_c, enc_a, enc_b);
    }
    time_end = chrono::high_resolution_clock::now();
    auto time_diff_add = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Add Time = [" << time_diff_add.count() / (10000) << " microseconds] " << endl;

    // Cal Enc(a)*k
    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < (10000); i++)
    {
        pcs_ep_mul(pk, mul_c, enc_a, b);
    }
    time_end = chrono::high_resolution_clock::now();
    auto time_diff_mul = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Mul Time = [" << time_diff_mul.count() / (10000) << " microseconds] " << endl;

    // Decryption Enc(a)+ Enc(b)
    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++)
    {
        pcs_decrypt(vk, c_add, add_c);
    }
    time_end = chrono::high_resolution_clock::now();
    auto time_diff_dec = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Dec_add Time = [" << time_diff_dec.count() / (1000) << " microseconds] " << endl;

    // Decryption Enc(a)*k
    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < (1000); i++)
    {
        pcs_decrypt(vk, c_mul, mul_c);
    }
    time_end = chrono::high_resolution_clock::now();
    auto time_diff_dec_mul = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Dec_mul Time = [" << time_diff_dec_mul.count() / (1000) << " microseconds] " << endl;

    // Enc(a) + b = Enc(a+b)
    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < (10000); i++)
    {
        pcs_ep_add(pk, add_result, enc_a, b);
    }
    time_end = chrono::high_resolution_clock::now();
    auto time_diff_ep_add = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Ep add Time = [" << time_diff_ep_add.count() / (10000) << " microseconds] " << endl;

    // Enc(a) - b = Enc(a-b)
    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < (10000); i++)
    {
        pcs_ep_sub(pk, sub_result, enc_a, b);
    }
    time_end = chrono::high_resolution_clock::now();
    auto time_diff_ep_sub = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Ep sub Time = [" << time_diff_ep_sub.count() / (10000) << " microseconds] " << endl;

    // left shift
    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < (100); i++)
    {
        pcs_ep_left_shift(pk, left_shift_result, enc_a, k);
    }
    time_end = chrono::high_resolution_clock::now();
    auto time_diff_left_shift = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Left shift Time = [" << time_diff_left_shift.count() / (100) << " microseconds] " << endl;

    // right shift
    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < (100); i++)
    {
        pcs_ep_right_shift(pk, vk, hr, right_shift_result, enc_a, k);
    }
    time_end = chrono::high_resolution_clock::now();
    auto time_diff_right_shift = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "right shift Time = [" << time_diff_right_shift.count() / (100) << " microseconds] " << endl;

    pcs_decrypt(vk, add_result, add_result);
    pcs_decrypt(vk, sub_result, sub_result);
    pcs_decrypt(vk, left_shift_result, left_shift_result);
    pcs_decrypt(vk, right_shift_result, right_shift_result);

    cout << '\n';
    cout << "plain add result is: " << result_a << '\n';
    cout << "plain mul result is: " << result_m << '\n';
    cout << "c add result is: " << c_add << '\n';
    cout << "c mul result is: " << c_mul << '\n';
    cout << "add_result: " << add_result << '\n';
    cout << "sub_result: " << sub_result << '\n';
    cout << "left_shift_result: " << left_shift_result << '\n';
    cout << "right_shift_result: " << right_shift_result << '\n';
    cout << "g: " << pk->g << '\n';
    cout << '\n';

    // Cleanup all data
    mpz_clears(a, b, c_add, c_mul, enc_a, enc_b, add_c, mul_c, result_a, result_m, add_result, sub_result, left_shift_result, right_shift_result, NULL);
    pcs_free_public_key(pk);
    pcs_free_private_key(vk);
    hcs_free_random(hr);

    return 0;
}
