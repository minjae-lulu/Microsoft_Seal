#include "libapcs.h"

void pcs_encrypt(pcs_public_key *pk, mpz_t rop, mpz_t plain1)
{
    mpz_t t1;
    mpz_init(t1);
    hcs_random *r = hcs_init_random();
    
    mpz_random_in_mult_group(t1, r->rstate, pk->n);
    mpz_powm(t1, t1, pk->n, pk->n2);
    mpz_powm(rop, pk->g, plain1, pk->n2);
    mpz_mul(rop, rop, t1);
    mpz_mod(rop, rop, pk->n2);

    mpz_clear(t1);
    gmp_randclear(r->rstate);
    free(r);
}


void pcs_ep_sub(pcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1, mpz_t g_inverse)
{
    mpz_powm(rop, g_inverse, plain1, pk->n2);
    mpz_mul(rop, cipher1, rop);
    mpz_mod(rop, rop, pk->n2);
}

void pcs_ep_left_shift(pcs_public_key *pk, mpz_t rop, mpz_t cipher1, unsigned int k)
{
    mpz_t two,plain1; 
    mpz_inits(two,plain1, NULL);

    if(k<30){
        mpz_set_ui(plain1,(2<<k)/2);
    }
    else{
        mpz_set_ui(two,2);
        mpz_pow_ui(plain1,two,k);
    }
    mpz_powm(rop, cipher1, plain1, pk->n2);
    mpz_clears(two, plain1, NULL);

}

void pcs_ep_right_shift(pcs_public_key *pk, pcs_private_key *vk, mpz_t rop, mpz_t cipher1, unsigned int k, int rlength, mpz_t g_inverse)
{

    mpz_t temp, r, two, two_k, r_twok, seed;
    mpz_inits(temp, r, two, two_k, r_twok, seed, NULL);
    gmp_randstate_t state2;
    gmp_randinit_mt(state2);

    mpz_seed(seed, HCS_RAND_SEED_BITS);
    gmp_randseed(state2, seed);
    mpz_urandomb(r, state2, rlength); // average m bit is 48. So we select r 88bit(48+40)


    if (k>=30){
        mpz_set_ui(two,2);
        mpz_pow_ui(two_k,two,k);
    }
    else{
        mpz_set_ui(two_k,((2<<k)/2));
    }
    mpz_mul(r,r,two_k);
    pcs_ep_add(pk, temp, cipher1, r);
    pcs_decrypt(vk, temp, temp);
    mpz_div(temp,temp,two_k);
    mpz_div(r_twok,r,two_k);
    pcs_encrypt(pk, temp, temp);  
    pcs_ep_sub(pk, rop, temp, r_twok, g_inverse);

    gmp_randclear(state2);
    mpz_clears(temp, r, two, two_k, r_twok, seed, NULL); 
}
