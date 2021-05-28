#include "utils.h"

using namespace std;
using namespace seal;

void ckks_module1();
void ckks_module2();
void ckks_module3a();
void ckks_module3b();

int main() {
//  ckks_module1();
  ckks_module2();
//  ckks_module3a();
//  ckks_module3b();
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

using namespace seal;

int attack() {

  // Define parameters
  uint32_t logN = 15; // (log of) ring size
  uint32_t scaleBits = 40; // (log of) the scale \Delta
  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 1 << logN;
  parms.set_poly_modulus_degree(poly_modulus_degree);

  // Fancy way of automatically setting the q_i's instead of providing a manual list
  int maxQBits = logN==16 ? 350 : CoeffModulus::MaxBitCount(poly_modulus_degree, sec_level_type::tc256);
  std::vector<int> modulusBits = {60}; // Set the first prime to be 60-bit
  int totalQBits = 60;
  while (totalQBits <= maxQBits - 60) {    // reserve the last special prime (60-bit)
    modulusBits.push_back(scaleBits);   // add a prime modulus of size == scaleBits
    totalQBits += scaleBits;
  }
  modulusBits.push_back(60);             // add the special prime modulus
  parms.set_coeff_modulus(CoeffModulus::Create(
      poly_modulus_degree, modulusBits));
  SEALContext context = SEALContext(parms);

  // Generate keys
  KeyGenerator keygen(context);
  PublicKey public_key;
  keygen.create_public_key(public_key);
  SecretKey secret_key = keygen.secret_key();
  RelinKeys relin_keys;
  keygen.create_relin_keys(relin_keys);
  GaloisKeys gal_keys;

  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);
  Decryptor decryptor(context, secret_key);
  CKKSEncoder encoder(context);
  size_t slot_count = encoder.slot_count();  // Let's use all the available slots

  // Set the initial scale
  double scale = pow(2.0, scaleBits);

  print_parameters(context, scale);

  // Encode numbers into a polynomial
  std::vector<cx_double> val_input(slot_count); //already filled with zeros
  Plaintext ptxt_input;
  encoder.encode(val_input, scale, ptxt_input);

  // Encrypt the plaintexts
  Ciphertext ctxt_input;
  encryptor.encrypt(ptxt_input, ctxt_input);

  // We don't perform any homomorphic operations
  auto ctxt_res = ctxt_input;

  // Decryption
  Plaintext ptxt_res;
  decryptor.decrypt(ctxt_res, ptxt_res); // approx decryption

  // Decode the plaintext polynomial
  std::vector<std::complex<double>> val_res;
  encoder.decode(ptxt_res, val_res);    // decode to an array of complex

  // Check computation errors
  std::vector<std::complex<double>> pt_res(slot_count);
  pt_res = val_input; // Since we performed no homomorphic computation
  std::cout << "computation error = " << maxDiff(pt_res, val_res)
            << ", relative error = " << relError(pt_res, val_res) << std::endl;

  // **************************************************
  // Key recovery attack
  // **************************************************

  // First we encode the decrypted floating point numbers back into polynomials
  Plaintext ptxt_enc;
  encoder.encode(val_res, ctxt_res.parms_id(), ctxt_res.scale(), ptxt_enc);

  // Then we get some useful parameters used in the scheme
  auto context_data = context.get_context_data(ctxt_res.parms_id());
  auto small_ntt_tables = context_data->small_ntt_tables();
  auto &ciphertext_parms = context_data->parms();
  auto &coeff_modulus = ciphertext_parms.coeff_modulus();
  size_t coeff_mod_count = coeff_modulus.size();
  size_t coeff_count = ciphertext_parms.poly_modulus_degree();

  // Check encoding error
  Plaintext ptxt_diff;
  ptxt_diff.parms_id() = parms_id_zero;
  ptxt_diff.resize(util::mul_safe(coeff_count, coeff_modulus.size()));
  sub(ptxt_enc.data(), ptxt_res.data(), coeff_count, coeff_modulus, ptxt_diff.data());
  to_coeff_rep(ptxt_diff.data(), coeff_count, coeff_mod_count, small_ntt_tables);
  long double err_norm = infty_norm(ptxt_diff.data(), context_data.get());
  std::cout << "encoding error = " << err_norm << std::endl;

  std::cout << "key recovery ..." << std::endl;
  MemoryPoolHandle pool = MemoryManager::GetPool();
  // rhs = ptxt_enc - ciphertext.b
  auto rhs = zero_polynomial(poly_modulus_degree, coeff_mod_count, pool);
  sub(ptxt_enc.data(), ctxt_res.data(0), coeff_count, coeff_modulus, rhs);

  auto ca = zero_polynomial(poly_modulus_degree, coeff_mod_count, pool);
  copy(ctxt_res.data(1), coeff_count, coeff_modulus.size(), ca);

  std::cout << "compute ca^{-1} ..." << std::endl;
  auto ca_inv = zero_polynomial(poly_modulus_degree, coeff_mod_count, pool);

  bool has_inv = inverse(ca, coeff_count, coeff_modulus, ca_inv);
  if (!has_inv) {
    throw std::logic_error("ciphertext[1] has no inverse");
  }

  // The recovered secret: key_guess = ciphertext.a^{-1} * rhs
  std::cout << "compute (m' - cb) * ca^{-1} ..." << std::endl;
  auto key_guess = zero_polynomial(poly_modulus_degree, coeff_mod_count, pool);
  multiply(rhs, ca_inv, coeff_count, coeff_modulus, key_guess);

  bool is_found = util::is_equal_uint(key_guess,
                                      secret_key.data().data(),
                                      coeff_count*coeff_mod_count);

  // In retrospect, let's see how big the re-encoded polynomial is
  to_coeff_rep(ptxt_enc.data(), coeff_count, coeff_mod_count, small_ntt_tables);
  std::cout << "m' norm bits = " << log2(l2_norm(ptxt_enc.data(), context_data.get())) << std::endl;

  return is_found;
}

void ckks_module2() {
  std::cout << "\n\n Module 2: Attacking the CKKS Scheme" << std::endl;

  int iterations = 10;
  int success = 0;
  for (int i = 0; i < iterations; i++) {
    if (attack()) {
      std::cout << "Found key!" << std::endl;
      success++;
    } else std::cout << "Attack failed!" << std::endl;
  }
  std::cout << "Attack worked " << success << " times out of " << iterations << std::endl;
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