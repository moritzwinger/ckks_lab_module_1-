// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void ckks_module2()
{
  print_example_banner("Module 2: CKKS Advanced");

  EncryptionParameters parms(scheme_type::ckks);

  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

  double scale = pow(2.0, 30);

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
   * We create plaintexts for 3.1, 4.1, 5.9 using an overload of CKKSEncoder::encode
   * that encodes the given floating-point value to every slot in the vector.
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
  Ciphertext ctxt_t;
  print_line(__LINE__);
  cout << "Compute (x+y) * (z+1) using ctxt-ctxt multiplication:" << endl;
  evaluator.multiply(ctxt_xPlusy, ctxt_zPlusOne, ctxt_t);
  cout << "Scale of (x+y)*(z+1): " << log2(ctxt_t.scale()) << " bits" << endl;

  /*
   * Compute (x+y) * (z+1) * 10 using ciphertext-plaintext multiplication:
   */
  Ciphertext ctxt_result;
  print_line(__LINE__);
  cout << "Compute (x+y) * (z+1) * 10  using ptxt-ctxt multiplication:" << endl;
  Plaintext ptxt_ten;
  encoder.encode(10, scale, ptxt_ten); //Note: original scale
  evaluator.rescale_to_next_inplace(ctxt_t);
  ctxt_t.scale() = pow(2.0, 30); // Manually override scale
  evaluator.mod_switch_to_inplace(ptxt_ten, ctxt_t.parms_id());
  cout << "Scale of (x+y) * (z+1) after rescaling: " << log2(ctxt_t.scale()) << " bits" << endl;
  evaluator.multiply_plain(ctxt_t, ptxt_ten, ctxt_result);
  cout << "Scale of (x+y) * (z+1) * 10: " << log2(ctxt_result.scale()) << " bits" << endl;

  /*
   * Decrypt, decode, and print the result.
   */
  Plaintext plain_result;
  decryptor.decrypt(ctxt_result, plain_result);
  vector<double> decoded_result;
  encoder.decode(plain_result, decoded_result);
  cout << "Computed result: " << decoded_result[0] << endl;
}
