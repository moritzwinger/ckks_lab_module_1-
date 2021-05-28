// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <seal/seal.h>
#include <seal/modulus.h>
#include <seal/util/iterator.h>


/*
Helper function: Prints the parameters in a SEALContext.
*/
inline void print_parameters(const seal::SEALContext &context, double scale)
{
    auto &context_data = *context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "|   scale: " << log2(scale)  << " bits " << std::endl;

    std::cout << "\\" << std::endl;
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
inline std::ostream &operator<<(std::ostream &stream, seal::parms_id_type parms_id)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    stream << std::hex << std::setfill('0') << std::setw(16) << parms_id[0] << " " << std::setw(16) << parms_id[1]
           << " " << std::setw(16) << parms_id[2] << " " << std::setw(16) << parms_id[3] << " ";

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);

    return stream;
}

/*
Helper function: Prints a vector of floating-point values.
*/
template <typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    std::size_t slot_count = vec.size();

    std::cout << std::fixed << std::setprecision(prec);
    std::cout << std::endl;
    if (slot_count <= 2 * print_size)
    {
        std::cout << "    [";
        for (std::size_t i = 0; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(std::max(vec.size(), 2 * print_size));
        std::cout << "    [";
        for (std::size_t i = 0; i < print_size; i++)
        {
            std::cout << " " << vec[i] << ",";
        }
        if (vec.size() > 2 * print_size)
        {
            std::cout << " ...,";
        }
        for (std::size_t i = slot_count - print_size; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    std::cout << std::endl;

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);
}

/*
Helper function: Print line number.
*/
inline void print_line(int line_number)
{
    std::cout << "Line " << std::setw(3) << line_number << " --> ";
}

/// Low-Level Utilities for Attack


typedef std::complex<double> cx_double;

void randomComplexVector(std::vector<cx_double>& array, size_t n, double rad = 1.0);
double largestElm(std::vector<cx_double> const& vec);
double maxDiff(std::vector<cx_double> const& in0, std::vector<cx_double> const& in1);
double relError(std::vector<cx_double> const& in0, std::vector<cx_double> const& in1);




// compute a^{-1}, where a is a double-CRT polynomial whose evaluation representation
// is in aEvalRep. The double-CRT representation in SEAL is stored as a flat array of
// length coeff_count * modulus_count:
//    [ 0 .. coeff_count-1 , coeff_count .. 2*coeff_count-1, ... ]
//      ^--- a (mod p0)    , ^--- a (mod p1),              ,  ...
// return if the inverse exists, and result is also in evaluation representation
bool inv_dcrtpoly(seal::util::ConstCoeffIter aEvalRep, std::size_t coeff_count, std::vector<seal::Modulus> const &coeff_modulus,
                  seal::util::CoeffIter result);

// compute a*b, where both a and b are in evaluation representation
void mul_dcrtpoly(seal::util::ConstCoeffIter a, seal::util::ConstCoeffIter b,
                  std::size_t coeff_count, std::vector<seal::Modulus> const &coeff_modulus,
                  seal::util::CoeffIter result);

// compute a+b, where both a and b are in the same representation
void add_dcrtpoly(seal::util::ConstCoeffIter a, seal::util::ConstCoeffIter b,
                  std::size_t coeff_count, std::vector<seal::Modulus> const &coeff_modulus,
                  seal::util::CoeffIter result);

// compute a-b, where both a and b are in the same representation
void sub_dcrtpoly(seal::util::ConstCoeffIter a, seal::util::ConstCoeffIter b,
                  std::size_t coeff_count, std::vector<seal::Modulus> const &coeff_modulus,
                  seal::util::CoeffIter result);

// assign result = a
void assign_dcrtpoly(seal::util::ConstCoeffIter a, std::size_t coeff_count, std::size_t coeff_modulus_count,
                     seal::util::CoeffIter result);

void to_eval_rep(seal::util::CoeffIter a,
                 size_t coeff_count,
                 size_t coeff_modulus_count,
                 seal::util::NTTTables const *small_ntt_tables);

void to_coeff_rep(seal::util::CoeffIter a,
                  size_t coeff_count,
                  size_t coeff_modulus_count,
                  seal::util::NTTTables const *small_ntt_tables);

long double infty_norm(seal::util::ConstCoeffIter a, seal::SEALContext::ContextData const *context_data);

long double l2_norm(seal::util::ConstCoeffIter a, seal::SEALContext::ContextData const *context_data);

std::string poly_to_string(std::uint64_t const *value, seal::EncryptionParameters const &parms);

void print_poly(std::uint64_t const *value, seal::EncryptionParameters const &parms, size_t max_count = 0);

template<typename T>
std::ostream &operator<<(std::ostream &os, const std::vector<T> &v) {
  using namespace std;
  os << "[";
  copy(v.begin(), v.end(), ostream_iterator<T>(os, ", "));
  os << "]";
  return os;
}