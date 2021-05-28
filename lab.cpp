#include "utils.h"

using namespace std;
using namespace seal;

void ckks_module1();
void ckks_module2();
void ckks_module3a();
void ckks_module3b();

int main() {
  ckks_module1();
  ckks_module2();
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

using namespace seal;

void print_parameters(const SEALContext &context) {
  auto &context_data = *context.key_context_data();
  std::cout << "Encryption parameters :" << std::endl;
  std::cout << "   poly_modulus_degree: " <<
            context_data.parms().poly_modulus_degree() << std::endl;
  // Print the size of the true (product) coefficient modulus.
  std::cout << "   coeff_modulus size: ";

  std::cout << context_data.total_coeff_modulus_bit_count() << " (";
  auto coeff_modulus = context_data.parms().coeff_modulus();
  std::size_t coeff_mod_count = coeff_modulus.size();
  for (std::size_t i = 0; i < coeff_mod_count - 1; i++) {
    std::cout << coeff_modulus[i].bit_count() << " + ";
  }

  std::cout << coeff_modulus.back().bit_count();
  std::cout << ") bits" << std::endl;
}

void evalVariance(Ciphertext &ctRes, Ciphertext const &ct, CKKSEncoder &encoder,
                  Evaluator &evaluator, RelinKeys const &relin_keys, GaloisKeys const &gal_keys,
                  uint32_t logBatchSize, double scale) {
  std::cout << "evalVariance size = " << (1 << logBatchSize) << std::endl;
  evaluator.square(ct, ctRes); // x^2
  evaluator.relinearize_inplace(ctRes, relin_keys);
  evaluator.rescale_to_next_inplace(ctRes);
  for (uint32_t i = 1; i <= logBatchSize; i++) {
    int shift = 1 << (logBatchSize - i);
    Ciphertext tmp;
    evaluator.rotate_vector(ctRes, -shift, gal_keys, tmp);
    evaluator.add_inplace(ctRes, tmp);
  }
  double factor = 1.0/((double) (1 << logBatchSize));
  Plaintext plain_factor;
  encoder.encode(factor, ctRes.parms_id(), scale, plain_factor);
  evaluator.multiply_plain_inplace(ctRes, plain_factor);
  evaluator.rescale_to_next_inplace(ctRes);
  // ctRes.scale() *= factor;
  std::cout << "final scale = " << log2(ctRes.scale()) << std::endl;
}

// ctRes[i] = encryption of x^(2^i), where ct = encryption of x, for 0 <= i <= logDeg
void evalPowerOf2(std::vector<Ciphertext> &ctRes, Ciphertext const &ct, int logDeg,
                  Evaluator &evaluator, RelinKeys const &relin_keys) {
  ctRes.resize(logDeg + 1);
  ctRes[0] = ct;                             // x^(2^0)
  for (int i = 1; i <= logDeg; i++) {
    evaluator.square(ctRes[i - 1], ctRes[i]); // x^(2^i)
    evaluator.relinearize_inplace(ctRes[i], relin_keys);
    evaluator.rescale_to_next_inplace(ctRes[i]); // mod (q0 .. q{-i})
  }
}


int attack(uint32_t logN = 15,      // Ring size
           uint32_t scaleBits = 40, // bit-length of the scaling factor
           double plainBound = 1.0, // bound on the plaintext numbers
           int32_t evalDeg = -1   // degree to evaluate, default to all
) {
  EncryptionParameters parms(scheme_type::ckks);   // Set the parameters for CKKS
  size_t poly_modulus_degree = 1 << logN;
  parms.set_poly_modulus_degree(poly_modulus_degree);

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
  print_parameters(context);

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

  // First we generate some random numbers
  std::vector<cx_double> val_input(slot_count);
  randomComplexVector(val_input, slot_count, plainBound);

  // Set the initial scale
  double scale = pow(2.0, scaleBits);

  // Encode plaintext numbers into a polynomial
  Plaintext ptxt_input;
  encoder.encode(val_input, scale, ptxt_input);
  Ciphertext ctxt_input;
  encryptor.encrypt(ptxt_input, ctxt_input);

  auto ctxt_res = ctxt_input;    // noop, just copy the input ciphertext

  // Now let's do approximate decryption and then recover the key
  Plaintext ptxt_res;
  decryptor.decrypt(ctxt_res, ptxt_res); // approx decryption

  // Decode the plaintext polynomial
  std::vector<std::complex<double>> val_res;
  encoder.decode(ptxt_res, val_res);    // decode to an array of complex

  // Check computation errors
  std::vector<std::complex<double>> pt_res(slot_count);
  pt_res = val_input;      // noop, just copy the plaintext input

  std::cout << "computation error = " << maxDiff(pt_res, val_res)
            << ", relative error = " << relError(pt_res, val_res) << std::endl;

  // **************************************************
  // Key recovery attack
  // **************************************************

  // First we encode the decrypted floating point numbers into polynomials
  Plaintext ptxt_enc;
  encoder.encode(val_res, ctxt_res.parms_id(), ctxt_res.scale(), ptxt_enc);

  // Then we get some impl parameters used in the scheme
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
  sub_dcrtpoly(ptxt_enc.data(), ptxt_res.data(), coeff_count, coeff_modulus, ptxt_diff.data());

  to_coeff_rep(ptxt_diff.data(), coeff_count, coeff_mod_count, small_ntt_tables);
  long double err_norm = infty_norm(ptxt_diff.data(), context_data.get());
  std::cout << "encoding error = " << err_norm << std::endl;

  // Now let's compute the secret key
  MemoryPoolHandle pool = MemoryManager::GetPool();
  std::cout << "key recovery ..." << std::endl;

  // rhs = ptxt_enc - ciphertext.b
  auto rhs(util::allocate_zero_poly(poly_modulus_degree, coeff_mod_count, pool));
  sub_dcrtpoly(ptxt_enc.data(), ctxt_res.data(0), coeff_count, coeff_modulus, rhs.get());

  auto ca(util::allocate_zero_poly(poly_modulus_degree, coeff_mod_count, pool));
  assign_dcrtpoly(ctxt_res.data(1), coeff_count, coeff_modulus.size(), ca.get());

  std::cout << "compute ca^{-1} ..." << std::endl;
  auto ca_inv(util::allocate_zero_poly(poly_modulus_degree, coeff_mod_count, pool));

  bool has_inv = inv_dcrtpoly(ca.get(), coeff_count, coeff_modulus, ca_inv.get());
  if (!has_inv) {
    throw std::logic_error("ciphertext[1] has no inverse");
  }

  // The recovered secret: key_guess = ciphertext.a^{-1} * rhs
  std::cout << "compute (m' - cb) * ca^{-1} ..." << std::endl;
  auto key_guess(util::allocate_zero_poly(poly_modulus_degree, coeff_mod_count, pool));
  mul_dcrtpoly(rhs.get(), ca_inv.get(), coeff_count, coeff_modulus, key_guess.get());

  bool is_found = util::is_equal_uint(key_guess.get(),
                                      secret_key.data().data(),
                                      coeff_count*coeff_mod_count);

  // In retrospect, let's see how big the re-encoded polynomial is
  to_coeff_rep(ptxt_enc.data(), coeff_count, coeff_mod_count, small_ntt_tables);
  std::cout << "m' norm bits = " << log2(l2_norm(ptxt_enc.data(), context_data.get())) << std::endl;

  return is_found;             // All done
}

void ckks_module2() {
  uint32_t logN = 15;      // ring size
  uint32_t scaleBits = 40; // bit-length of scale
  double plainBound = 1.0; // upper bound on plaintext numbers
  int32_t evalDeg = -1;    // degree to evaluate, default to all


  int iterations = 100;

  int success = 0;
  for (int i = 0; i < iterations; i++) {
    if (attack(logN, scaleBits, plainBound, evalDeg)) {
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