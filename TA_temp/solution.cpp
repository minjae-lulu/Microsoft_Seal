#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "math.h"
#include "time.h"
#include <random>
#include <chrono>
#include <sys/resource.h>
#include "seal/seal.h"

using namespace std;
using namespace seal;

int main(int argc, char* argv[])
{
    cout << "+------------------------------------+" << endl;
    cout << "|           Key Generation           |" << endl;
    cout << "+------------------------------------+" << endl;
    
    EncryptionParameters parms(scheme_type::ckks);
    
    size_t poly_modulus_degree = (1 << 13);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Choose coeff_modulus
    int logq = 40;
    int logq0 = 50;
    
    vector<int> modulus_size = {logq0, logq, logq, logq0};
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, modulus_size));
   
    double scale = pow(2.0, logq);

    SEALContext context(parms);
   
    // choose random homomophic encryption keys
    KeyGenerator keygen(context);
    
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
 
    cout << "+------------------------------------+" << endl;
    cout << "|         Encryption (data)          |" << endl;
    cout << "+------------------------------------+" << endl;
    
    vector<double> input1 {0.1, 0.2, 0.3};
    vector<double> input2 {0.2, 0.3, 0.4};
    
    cout << "Input1: [";
    for(int i = 0; i < 3; i++){
        cout << input1[i] << ((i != 2) ? "," : "]\n");
    }
    cout << "Input2: [";
    for(int i = 0; i < 3; i++){
        cout << input2[i] << ((i != 2) ? "," : "]\n");
    }
    
#if 0
    Plaintext plaintext1;
    encoder.encode(input1, scale, plaintext1);
    Ciphertext ciphertext1;
    encryptor.encrypt(plaintext1, ciphertext1);
    
    Plaintext plaintext2;
    encoder.encode(input2, scale, plaintext2);
    Ciphertext ciphertext2;
    encryptor.encrypt(plaintext2, ciphertext2);
#endif
   
#if 0
    cout << "+------------------------------------+" << endl;
    cout << "|           Evaluation - add         |" << endl;
    cout << "+------------------------------------+" << endl;
    
    Ciphertext add_ciphertext;
    evaluator.add(ciphertext1, ciphertext2, add_ciphertext);
    
    // decryption
    Plaintext plaintext_result; // plaintext for decryption
    vector<double> result;  // plain vector for decryption
    
    decryptor.decrypt(add_ciphertext, plaintext_result);
    encoder.decode(plaintext_result, result);

    cout << "Add: [";
    for(int i = 0; i < 3; i++){
        cout << result[i] << ((i != 2) ? "," : "]\n");
    }
#endif
    
#if 0
    cout << "+------------------------------------+" << endl;
    cout << "|          Evaluation - mult         |" << endl;
    cout << "+------------------------------------+" << endl;
    
    Ciphertext mult_ciphertext;
    evaluator.multiply(ciphertext1, ciphertext2, mult_ciphertext);
    evaluator.relinearize_inplace(mult_ciphertext, relin_keys);
    evaluator.rescale_to_next_inplace(mult_ciphertext);
    
    decryptor.decrypt(mult_ciphertext, plaintext_result);
    encoder.decode(plaintext_result, result);

    cout << "mult: [";
    for(int i = 0; i < 3; i++){
        cout << result[i] << ((i != 2) ? "," : "]\n");
    }
#endif
    
#if 0
    cout << "+------------------------------------+" << endl;
    cout << "|          Evaluation - rot         |" << endl;
    cout << "+------------------------------------+" << endl;
    
    // rotation by one
    Ciphertext rot_ciphertext;
    evaluator.rotate_vector(ciphertext1, 1, gal_keys, rot_ciphertext);
    
    decryptor.decrypt(rot_ciphertext, plaintext_result);
    encoder.decode(plaintext_result, result);
    
    cout << "rot by 1: [";
    for(int i = 0; i < 3; i++){
        cout << result[i] << ((i != 2) ? "," : "]\n");
    }
#endif
    
#if 0
    // rotation by two
    evaluator.rotate_vector(ciphertext1, 2, gal_keys, rot_ciphertext);
    
    decryptor.decrypt(rot_ciphertext, plaintext_result);
    encoder.decode(plaintext_result, result);
    
    cout << "rot by 2: [";
    for(int i = 0; i < 3; i++){
        cout << result[i] << ((i != 2) ? "," : "]\n");
    }
#endif
 
#if 1
    cout << "+------------------------------------+" << endl;
    cout << "|         rot-and-sum (trial)        |" << endl;
    cout << "+------------------------------------+" << endl;
    
    vector<double> input {0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1}; // input
   
    cout << "Input: [";
    for(int i = 0; i < 8; i++){
        cout << input[i] << ((i != 7) ? "," : "]\n");
    }
    
    Plaintext plaintext;
    encoder.encode(input, scale, plaintext); // encode
    
    Ciphertext rs_ciphertext;
    encryptor.encrypt(plaintext, rs_ciphertext); // encrypt
    
    Ciphertext temp;
    evaluator.rotate_vector(rs_ciphertext, 1, gal_keys, temp);
    evaluator.add(rs_ciphertext, temp, rs_ciphertext);
    
    evaluator.rotate_vector(rs_ciphertext, 2, gal_keys, temp);
    evaluator.add(rs_ciphertext, temp, rs_ciphertext);
    
    evaluator.rotate_vector(rs_ciphertext, 4, gal_keys, temp);
    evaluator.add(rs_ciphertext, temp, rs_ciphertext);
    
    // decryption
    Plaintext rs_plaintext_result; // plaintext for decryption
    vector<double> rs_result;  // plain vector for decryption
    decryptor.decrypt(rs_ciphertext, rs_plaintext_result);
    encoder.decode(rs_plaintext_result, rs_result);
    
    cout << "rot-and-sum (trial): [";
    for(int i = 0; i < 8; i++){
        cout << rs_result[i] << ((i != 7) ? "," : "]\n");
    }
  
#endif
    
#if 1
    cout << "+------------------------------------+" << endl;
    cout << "|            rot-and-sum             |" << endl;
    cout << "+------------------------------------+" << endl;
    
    vector<double> new_input;
    
    for(int i = 0; i < slot_count; i++){
        new_input.push_back(input[i % 8]);
    }

    encoder.encode(new_input, scale, plaintext); // encode

    encryptor.encrypt(plaintext, rs_ciphertext); // encrypt

    evaluator.rotate_vector(rs_ciphertext, 1, gal_keys, temp);
    evaluator.add(rs_ciphertext, temp, rs_ciphertext);

    evaluator.rotate_vector(rs_ciphertext, 2, gal_keys, temp);
    evaluator.add(rs_ciphertext, temp, rs_ciphertext);

    evaluator.rotate_vector(rs_ciphertext, 4, gal_keys, temp);
    evaluator.add(rs_ciphertext, temp, rs_ciphertext);

    // decryption
    decryptor.decrypt(rs_ciphertext, rs_plaintext_result);
    encoder.decode(rs_plaintext_result, rs_result);

    cout << "rot-and-sum: [";
    for(int i = 0; i < 8; i++){
        cout << rs_result[i] << ((i != 7) ? "," : "]\n");
    }
   
    for(int i = 8; i < 16; i++){
        cout << rs_result[i] << ((i != 15) ? "," : "]\n");
    }
#endif
    return 0;
}
