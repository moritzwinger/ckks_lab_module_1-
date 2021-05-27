// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_ckks_basics()
{
  print_example_banner("Module 1: CKKS Basics");

  EncryptionParameters parms(scheme_type::ckks);

  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

  double scale = pow(2.0, 60);

  SEALContext context(parms);
  print_parameters(context);
  cout << endl;

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

  /*
  We create plaintexts for 3.1, 4.1, 5.9 using an overload of CKKSEncoder::encode
  that encodes the given floating-point value to every slot in the vector.
  */
  Plaintext plain_x, plain_y, plain_z;
  encoder.encode(3.1, scale, plain_x);
  encoder.encode(4.1, scale, plain_y);
  encoder.encode(5.9, scale, plain_z);

  Ciphertext ctxt_x, ctxt_y, ctxt_z;

  encryptor.encrypt(plain_x, ctxt_x);
  encryptor.encrypt(plain_y, ctxt_y);
  encryptor.encrypt(plain_z, ctxt_z);

  /*
   * Calculate x+y via ciphertext-ciphertext addition:
   */
  Ciphertext ctxt_xPlusy;
  print_line(__LINE__);
  cout << "Compute x+y using ctxt-ctxt addition:" << endl;
  evaluator.add(ctxt_x, ctxt_y, ctxt_xPlusy);
  cout << "Scale of x+y: " << log2(ctxt_xPlusy.scale()) << " bits" << endl;

  /*
   * Calculate z+1 using ciphertext-plaintext addition
   */
  Ciphertext ctxt_zPlusOne;
  print_line(__LINE__);
  cout << "Compute z+1 using ctxt-ptxt addition:" << endl;
  Plaintext plain_one;
  encoder.encode(1, scale, plain_one);
  evaluator.add_plain(ctxt_z, plain_one, ctxt_zPlusOne);
  cout << "Scale of z+1: " << log2(ctxt_zPlusOne.scale()) << " bits" << endl;

  /*
   * Calculate (x+y) * (z+1) using ciphertext-ciphertext multiplication
   */
  Ciphertext ctxt_mult1;
  print_line(__LINE__);
  cout << "Compute (x+y) * (z+1) using ctxt-ctxt multiplication:" << endl;
  evaluator.multiply(ctxt_xPlusy, ctxt_zPlusOne, ctxt_mult1);
  cout << "Scale of (x+y)*(z+1): " << log2(ctxt_mult1.scale()) << " bits" << endl;

 /*
  * Compute (x+y) * (z+1) * 10 using ciphertext-ciphertext multiplication:
  */
  Ciphertext ctxt_result;
  print_line(__LINE__);
  cout << "Compute (x+y) * (z+1) * 10  using ctxt-ctxt addition:" << endl;
  Plaintext plain_ten;
  encoder.encode(10, pow(2,120), plain_ten); //Note: different scale
  evaluator.add_plain(ctxt_mult1, plain_ten, ctxt_result);
  cout << "Scale of (x+y) * (z+1) * 10: " << log2(ctxt_result.scale()) << " bits" << endl;

  /*
   Decrypt, decode, and print the result.
   */
  Plaintext plain_result;
  decryptor.decrypt(ctxt_result, plain_result);
  vector<double> decoded_result;
  encoder.decode(plain_result, decoded_result);
  cout << "Computed result: " << decoded_result[0] << endl;

}
