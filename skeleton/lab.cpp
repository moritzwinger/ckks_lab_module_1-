#include "utils.h"

using namespace std;
using namespace seal;

void ckks_module1();
void ckks_module2();

int main() {
  ckks_module1();
  ckks_module2();
  //TODO: Module 3 & 4
  return 0;
}

void ckks_module1() {
  cout << "\n\n Module 1: Ciphertext-Plaintext" << endl;
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

  //TODO: Compute ((x+y)*(z*5))+10 for x=3.1, y=4.1 and z=5.9

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

  Ciphertext ctxt_res;
  //TODO: Encode a vector of zeros, encrypt it (into ctxt_res) and then decrypt & decode it
  // Optional: Compute the encoding/decoding error

  // **************************************************
  // Key recovery attack
  // **************************************************

  Plaintext ptxt_enc;
  // TODO: Encode the vector of complex numbers you just got back into a plaintext (ptxt_enc)
  //  Optional: Compute the error again

  // Some useful parameters used in the scheme
  auto context_data = context.get_context_data(ctxt_res.parms_id());
  auto small_ntt_tables = context_data->small_ntt_tables();
  auto &ciphertext_parms = context_data->parms();
  auto &coeff_modulus = ciphertext_parms.coeff_modulus();
  size_t coeff_mod_count = coeff_modulus.size();
  size_t coeff_count = ciphertext_parms.poly_modulus_degree();

  // Create a memory pool which all seal_polynomial's will share
  MemoryPoolHandle pool = MemoryManager::GetPool();

  seal_polynomial key_guess = zero_polynomial(poly_modulus_degree, coeff_mod_count, pool);
  // TODO: Calculate the secret key as described in the lab sheet

  // Confirm that the key is correct
  return util::is_equal_uint(key_guess, secret_key.data().data(), coeff_count*coeff_mod_count);
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