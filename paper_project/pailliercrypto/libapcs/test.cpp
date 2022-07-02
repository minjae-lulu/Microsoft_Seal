#define CATCH_CONFIG_RUNNER

#include <string.h>
#include <ctype.h>
#include <iostream>

#include <libhcs.h>
#include <gmpxx.h>
#include "../libhcs/test/catch.hpp"
#include "../libhcs/include/libhcs++/pcs.hpp"
#include "libapcs.h"
using namespace std;

static hcs::random *hr;
static hcs::pcs::public_key *pk;
static hcs::pcs::private_key *vk;

// if you want more information about function you should see pcs.c. and libapcs.cpp
int main(void)
{
    // initialize data structures
    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();
    hcs_random *hr = hcs_init_random();

    // Generate a key pair with modulus of size 2048 bits
    pcs_generate_key_pair(pk, vk, hr, 2048);

    // libhcs works directly with gmp mpz_t types, so initialize some
    mpz_t g_inverse;
    mpz_init(g_inverse);
    mpz_invert(g_inverse, pk->g, pk->n2); // g_inverse is for ep_sub function

    mpz_t a, b, cta, ctb, ee_add, ep_add, ep_sub, ep_mul, left_a, right_a;
    mpz_inits(a, b, cta, ctb, ee_add, ep_add, ep_sub, ep_mul, left_a, right_a, NULL);
    unsigned int k = 0;

    cout << "input a and b and const k: ";
    cin >> a >> b >> k;

    pcs_encrypt(pk, cta, a); // Encrypt a
    pcs_encrypt(pk, ctb, b); // Encrypt b
    cout << "encrypt a is: " << cta << '\n';
    cout << "encrypt b is: " << ctb << '\n';

    pcs_ee_add(pk, ee_add, cta, ctb);          // enc(a) + enc(b)
    pcs_ep_add(pk, ep_add, cta, b);            // enc(a) + b
    pcs_ep_sub(pk, ep_sub, cta, b, g_inverse); // enc(a) - b
    pcs_ep_mul(pk, ep_mul, cta, b);            //  enc(a) * b
    // cout << "ee_add is: " << ee_add << '\n';
    // cout << "ep_add is: " << ep_add << '\n';
    // cout << "ep_sub is: " << ep_sub << '\n';
    // cout << "ep_mul is: " << ep_mul << '\n';

    pcs_ep_left_shift(pk, left_a, cta, k);                      // left_shift encrypted a
    pcs_ep_right_shift(pk, vk, right_a, cta, k, 88, g_inverse); //right_shift encrypted a
    // cout << "left shift cta is: " << left_a << '\n';
    // cout << "right shift cta is: " << right_a << '\n';

    pcs_decrypt(vk, cta, cta); // decrypt enc(a)
    pcs_decrypt(vk, ctb, ctb); // decrypt enc(b)
    pcs_decrypt(vk, ee_add, ee_add);
    pcs_decrypt(vk, ep_add, ep_add);
    pcs_decrypt(vk, ep_sub, ep_sub);
    pcs_decrypt(vk, ep_mul, ep_mul);
    pcs_decrypt(vk, left_a, left_a);
    pcs_decrypt(vk, right_a, right_a);

    cout << "decrypt a is: " << cta << '\n';
    cout << "decrypt b is: " << ctb << '\n';
    cout << "dec right shift cta is: " << right_a << '\n';

    // Cleanup all data
    mpz_clears(a, b, cta, ctb, ee_add, ep_add, ep_sub, ep_mul, left_a, right_a, NULL);
    mpz_clear(g_inverse);
    pcs_free_public_key(pk);
    pcs_free_private_key(vk);
    hcs_free_random(hr);

    return 0;
}
