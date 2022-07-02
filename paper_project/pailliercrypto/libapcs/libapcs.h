#ifndef LIBAPCS_H
#define LIBAPCS_H

#include "../libhcs/include/libhcs/pcs.h"
#include "../libhcs/include/libhcs++/pcs.hpp"

#include "../libhcs/src/com/omp.h"
#include "../libhcs/src/com/parson.h"
#include "../libhcs/src/com/util.h"

/**
 * Encrypt a value @p plain1, and set @p rop to the encrypted result.
 *
 * @param pk A pointer to an initialised pcs_public_key
 * @param rop mpz_t where the encrypted result is stored
 * @param plain1 mpz_t to be encrypted
 */
void pcs_encrypt(pcs_public_key *pk, mpz_t rop, mpz_t plain1);

/**
 * Sub a plaintext value @p plain1 to an encrypted value @p cipher1, storing
 * the result in @p rop.
 *
 * @param pk A pointer to an initialised pcs_public_key
 * @param rop mpz_t where the newly encrypted value is stored
 * @param cipher1 mpz_t to be substracted
 * @param plain1 mpz_t to substract
 * @param g_inverse is g^-1
 */
void pcs_ep_sub(pcs_public_key *pk, mpz_t rop, mpz_t cipher1, mpz_t plain1, mpz_t g_inverse);

/**
 * left shift a chipertext value @p cipher1 moved by unsigned int @p k, 
 * storing the result in @p rop 
 *
 * @param pk A pointer to an initialised pcs_public_key
 * @param rop mpz_t where the newly left shift value is stored
 * @param cipher1 mpz_t to be leftshifted
 * @param k unsigned int k
 */
void pcs_ep_left_shift(pcs_public_key *pk, mpz_t rop, mpz_t cipher1, unsigned int k);

/**
 * right shift a chipertext value @p cipher1 moved by unsigned int @p k, 
 * storing the result in @p rop 
 * road is : // E(m) -> E(m+r) - > D(E(m+r)) = m+r -> m+r/2^k -> E(m+r/2^k) -> D(E(m+r/2^k - r/2^k)) -> m/2^k
 * 
 * @param pk A pointer to an initialised pcs_public_key
 * @param vk A pointer to an initialised pcs_private_key
 * @param rop mpz_t where the newly right shift value is stored
 * @param cipher1 mpz_t to be right shifted
 * @param k unsigned int k
 * @param rlength rlength is random length (recommend average bit + 40)
 * @param g_inverse is g^-1
 */
void pcs_ep_right_shift(pcs_public_key *pk, pcs_private_key *vk, mpz_t rop, mpz_t cipher1, unsigned int k, int rlength, mpz_t g_inverse);

#endif
