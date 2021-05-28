#include "util.h"

using namespace std;
using namespace seal;

void ckks_module1();
void ckks_module3a();
void ckks_module3b();

int main() {
  ckks_module1();
  ckks_module3a();
  ckks_module3b();
  return 0;
}

void ckks_module1() {
  cout << "\n\n Module 1: Ciphertext-Plaintext without rescaling!" << endl;
  EncryptionParameters parms(scheme_type::ckks);

  size_t poly_modulus_degree = 16384;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {30, 30, 30, 30, 30}));
  double scale = pow(2.0, 30);;

  SEALContext context(parms);
  print_parameters(context, scale);
  cout << endl;

  KeyGenerator keygen(context);
  auto secret_key = keygen.secret_key();
  PublicKey public_key;
  keygen.create_public_key(public_key);
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
   * Calculate z*5 using ciphertext-plaintext multiplication
   */
  Ciphertext ctxt_zTimesFive;
  print_line(__LINE__);
  cout << "Compute z*5 using ctxt-ptxt multiplication:" << endl;
  Plaintext plain_five;
  encoder.encode(5, scale, plain_five);
  evaluator.multiply_plain(ctxt_z, plain_five, ctxt_zTimesFive);
  cout << "Scale of z*5: " << log2(ctxt_zTimesFive.scale()) << " bits" << endl;

  /*
   * Calculate (x+y) * (z*5) using ciphertext-ciphertext multiplication
   */
  Ciphertext ctxt_t;
  print_line(__LINE__);
  cout << "Compute (x+y) * (z*5) using ctxt-ctxt multiplication:" << endl;
  evaluator.multiply(ctxt_xPlusy, ctxt_zTimesFive, ctxt_t);
  cout << "Scale of (x+y)*(z*5): " << log2(ctxt_t.scale()) << " bits" << endl;

  /*
   * Try to compute ((x+y) * (z*5)) + 10 using ciphertext-plaintext addition:
   */
  try {
    Ciphertext ctxt_result;
    print_line(__LINE__);
    cout << "Trying to compute ((x+y) * (z*5)) + 10 using ciphertext-plaintext addition:" << endl;
    Plaintext plain_ten;
    encoder.encode(10, scale, plain_ten);
    evaluator.add_plain(ctxt_t, plain_ten, ctxt_result);
  } catch (const std::exception &e) {
    print_line(__LINE__);
    cout << "Computing ((x+y) * (z*5)) + 10 using ciphertext-plaintext addition failed: " << e.what() << endl;
  }

  /*
  * Compute ((x+y) * (z*5)) + 10 using ciphertext-plaintext addition and encoding at scale^3:
  */
  Ciphertext ctxt_result;
  print_line(__LINE__);
  cout << "Compute ((x+y) * (z*5)) + 10 using ciphertext-plaintext addition and encoding at scale^3:" << endl;
  Plaintext plain_ten;
  encoder.encode(10, pow(scale, 3.0), plain_ten);
  evaluator.add_plain(ctxt_t, plain_ten, ctxt_result);
  cout << "Scale of ((x+y) * (z*5)) + 10: " << log2(ctxt_result.scale()) << " bits" << endl;

  /*
   * Decrypt, decode, and print the result.
   */
  Plaintext plain_result;
  decryptor.decrypt(ctxt_result, plain_result);
  vector<double> decoded_result;
  encoder.decode(plain_result, decoded_result);
  cout << "Computed result: " << decoded_result[0] << endl;
}

void ckks_module3a() {
  cout << "\n\n Module 3a: Encrypted 10" << endl;
  EncryptionParameters parms(scheme_type::ckks);

  size_t poly_modulus_degree = 16384;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {30, 30, 30, 30, 30}));
  double scale = pow(2.0, 30);;

  SEALContext context(parms);
  print_parameters(context, scale);
  cout << endl;

  KeyGenerator keygen(context);
  auto secret_key = keygen.secret_key();
  PublicKey public_key;
  keygen.create_public_key(public_key);
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
  * Encrypt 10, too
  */
  Plaintext plain_ten;
  encoder.encode(10, scale, plain_ten);
  Ciphertext ctxt_ten;
  encryptor.encrypt(plain_ten, ctxt_ten);

  /*
   * Calculate x+y via ciphertext-ciphertext addition:
   */
  Ciphertext ctxt_xPlusy;
  print_line(__LINE__);
  cout << "Compute x+y using ctxt-ctxt addition:" << endl;
  evaluator.add(ctxt_x, ctxt_y, ctxt_xPlusy);
  cout << "Scale of x+y: " << log2(ctxt_xPlusy.scale()) << " bits" << endl;

  /*
   * Calculate z*5 using ciphertext-plaintext multiplication
   */
  Ciphertext ctxt_zTimesFive;
  print_line(__LINE__);
  cout << "Compute z*5 using ctxt-ptxt multiplication:" << endl;
  Plaintext plain_five;
  encoder.encode(5, scale, plain_five);
  evaluator.multiply_plain(ctxt_z, plain_five, ctxt_zTimesFive);
  cout << "Scale of z*5: " << log2(ctxt_zTimesFive.scale()) << " bits" << endl;

  /*
   * Calculate (x+y) * (z*5) using ciphertext-ciphertext multiplication
   */
  Ciphertext ctxt_t;
  print_line(__LINE__);
  cout << "Compute (x+y) * (z*5) using ctxt-ctxt multiplication:" << endl;
  evaluator.multiply(ctxt_xPlusy, ctxt_zTimesFive, ctxt_t);
  cout << "Scale of (x+y)*(z*5): " << log2(ctxt_t.scale()) << " bits" << endl;


  /*
  * Rescale ((x+y) * (z*5))
  */
  print_line(__LINE__);
  cout << "Rescale (x+y) * (z*5) down:" << endl;
  evaluator.rescale_to_next_inplace(ctxt_t); //approx. scale^2
  evaluator.rescale_to_next_inplace(ctxt_t); //approx. scale
  cout << "Scale of (x+y) * (z*5) after rescaling: " << log2(ctxt_t.scale()) << " bits" << endl;


  /*
   * Try to compute ((x+y) * (z*5)) + 10 using ciphertext-ciphertext addition:
   */
  try {
    Ciphertext ctxt_result;
    print_line(__LINE__);
    cout << "Trying to compute ((x+y) * (z*5)) + 10 using ciphertext-ciphertext addition:" << endl;
    evaluator.add(ctxt_t, ctxt_ten, ctxt_result);
  } catch (const std::exception &e) {
    print_line(__LINE__);
    cout << "Computing ((x+y) * (z*5)) + 10 using ciphertext-ciphertext addition failed: " << e.what() << endl;
  }

  /*
  * Mod-switch ctxt_ten down:
  */
  print_line(__LINE__);
  cout << "Mod-switch ctxt_ten down:" << endl;
  evaluator.mod_switch_to_next_inplace(ctxt_ten);
  evaluator.mod_switch_to_next_inplace(ctxt_ten); //twice, just as we had to rescale twice


  /*
   * Try to compute ((x+y) * (z*5)) + 10 using ciphertext-ciphertext addition after mod-switching:
   */
  try {
    Ciphertext ctxt_result;
    print_line(__LINE__);
    cout << "Trying to compute ((x+y) * (z*5)) + 10 using ciphertext-ciphertext addition after mod-switching:" << endl;
    evaluator.add(ctxt_t, ctxt_ten, ctxt_result);
  } catch (const std::exception &e) {
    print_line(__LINE__);
    cout << "Computing ((x+y) * (z*5)) + 10 using ciphertext-ciphertext addition after mod-switching failed: "
         << e.what() << endl;
  }


  /*
  * Override scale of ((x+y) * (z*5)):
  */
  print_line(__LINE__);
  ctxt_t.scale() = scale; // Manually override scale
  cout << "Scale of (x+y) * (z*5) manually set to: " << log2(ctxt_t.scale()) << " bits" << endl;


  /*
  * Compute ((x+y) * (z*5)) + 10 using ciphertext-ciphertext addition after setting scale:
  */
  Ciphertext ctxt_result;
  print_line(__LINE__);
  cout << "Compute ((x+y) * (z*5)) + 10 using ciphertext-ciphertext addition after setting scale:" << endl;
  evaluator.add(ctxt_t, ctxt_ten, ctxt_result);
  cout << "Scale of ((x+y) * (z*5)) + 10: " << log2(ctxt_result.scale()) << " bits" << endl;

  /*
   * Decrypt, decode, and print the result.
   */
  Plaintext plain_result;
  decryptor.decrypt(ctxt_result, plain_result);
  vector<double> decoded_result;
  encoder.decode(plain_result, decoded_result);
  cout << "Computed result: " << decoded_result[0] << endl;
}

void ckks_module3b() {
  cout << "\n\n Module 3b: Encrypted 10 and 5" << endl;
  EncryptionParameters parms(scheme_type::ckks);

  size_t poly_modulus_degree = 16384;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {30, 30, 30, 30, 30}));
  double scale = pow(2.0, 30);

  SEALContext context(parms);
  print_parameters(context, scale);
  cout << endl;

  KeyGenerator keygen(context);
  auto secret_key = keygen.secret_key();
  PublicKey public_key;
  keygen.create_public_key(public_key);
  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);
  Decryptor decryptor(context, secret_key);


  /*
   * Generate Relinearization Keys
   */
  RelinKeys relin_keys;
  keygen.create_relin_keys(relin_keys);

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
  * Encrypt 10, too
  */
  Plaintext plain_ten;
  encoder.encode(10, scale, plain_ten);
  Ciphertext ctxt_ten;
  encryptor.encrypt(plain_ten, ctxt_ten);

  /*
  * Encrypt 5, too
  */
  Plaintext plain_five;
  encoder.encode(5, scale, plain_five);
  Ciphertext ctxt_five;
  encryptor.encrypt(plain_five, ctxt_five);

  /*
   * Calculate x+y via ciphertext-ciphertext addition:
   */
  Ciphertext ctxt_xPlusy;
  print_line(__LINE__);
  cout << "Compute x+y using ctxt-ctxt addition:" << endl;
  evaluator.add(ctxt_x, ctxt_y, ctxt_xPlusy);
  cout << "Scale of x+y: " << log2(ctxt_xPlusy.scale()) << " bits" << endl;

  /*
   * Calculate z*5 using ciphertext-ciphertext multiplication
   */
  Ciphertext ctxt_zTimesFive;
  print_line(__LINE__);
  cout << "Compute z*5 using ctxt-ctxt multiplication:" << endl;
  evaluator.multiply(ctxt_z, ctxt_five, ctxt_zTimesFive);
  cout << "Scale of z*5: " << log2(ctxt_zTimesFive.scale()) << " bits" << endl;

  /*
  * Relinearize z*5
  * Note: In this toy example, relinearization does not actually make any noticeable difference
  */
  print_line(__LINE__);
  cout << "Relinearize z*:" << endl;
  evaluator.relinearize_inplace(ctxt_zTimesFive, relin_keys);

  /*
   * Calculate (x+y) * (z*5) using ciphertext-ciphertext multiplication
   */
  Ciphertext ctxt_t;
  print_line(__LINE__);
  cout << "Compute (x+y) * (z*5) using ctxt-ctxt multiplication:" << endl;
  evaluator.multiply(ctxt_xPlusy, ctxt_zTimesFive, ctxt_t);
  cout << "Scale of (x+y)*(z*5): " << log2(ctxt_t.scale()) << " bits" << endl;


  /*
  * Rescale ((x+y) * (z*5))
  */
  print_line(__LINE__);
  cout << "Rescale (x+y) * (z*5) down:" << endl;
  evaluator.rescale_to_next_inplace(ctxt_t); //approx. scale^2
  evaluator.rescale_to_next_inplace(ctxt_t); //approx. scale
  cout << "Scale of (x+y) * (z*5) after rescaling: " << log2(ctxt_t.scale()) << " bits" << endl;


  /*
  * Mod-switch ctxt_ten down:
  */
  print_line(__LINE__);
  cout << "Mod-switch ctxt_ten down:" << endl;
  evaluator.mod_switch_to_next_inplace(ctxt_ten);
  evaluator.mod_switch_to_next_inplace(ctxt_ten); //twice, just as we had to rescale twice


  /*
  * Override scale of ((x+y) * (z*5)):
  */
  print_line(__LINE__);
  ctxt_t.scale() = scale; // Manually override scale
  cout << "Scale of (x+y) * (z*5) manually set to: " << log2(ctxt_t.scale()) << " bits" << endl;


  /*
  * Compute ((x+y) * (z*5)) + 10 using ciphertext-ciphertext addition after setting scale:
  */
  Ciphertext ctxt_result;
  print_line(__LINE__);
  cout << "Compute ((x+y) * (z*5)) + 10 using ciphertext-ciphertext addition after setting scale:" << endl;
  evaluator.add(ctxt_t, ctxt_ten, ctxt_result);
  cout << "Scale of ((x+y) * (z*5)) + 10: " << log2(ctxt_result.scale()) << " bits" << endl;

  /*
   * Decrypt, decode, and print the result.
   */
  Plaintext plain_result;
  decryptor.decrypt(ctxt_result, plain_result);
  vector<double> decoded_result;
  encoder.decode(plain_result, decoded_result);
  cout << "Computed result: " << decoded_result[0] << endl;
}