#include "context.h"

#include <stdlib.h>

#include <functional>
#include <memory>
#include <string>

#include "backend_logging.h"
#include "ctxt.h"
#include "ptxt.h"
#include "seal/seal.h"
#include "utils/utils.h"

namespace {

const std::string BACKEND_NAME = "SEAL Backend";
const seal::SEALVersion sv;
const std::string BACKEND_STRING =
    BACKEND_NAME + " using SEAL " + std::to_string(sv.major) + "." +
    std::to_string(sv.minor) + "." + std::to_string(sv.patch);

void coeff_modulus_to_stringstream(
    std::stringstream& ss, const std::vector<seal::Modulus>& coeff_moduls,
    bool bits) {
  size_t n = 0;
  ss << "[";
  for (const seal::Modulus& cm : coeff_moduls) {
    if (bits) {
      ss << cm.bit_count();
    } else {
      ss << cm.value();
    }
    if (n != coeff_moduls.size() - 1) {
      ss << ", ";
    }
  }
  ss << "]";
}

}  // namespace

namespace aluminum_shark {
// template specialization
template <>
CONTENT_TYPE type_to_content_type<long>() {
  return CONTENT_TYPE::LONG;
}

template <>
CONTENT_TYPE type_to_content_type<double>() {
  return CONTENT_TYPE::DOUBLE;
}

SEALContext::SEALContext(seal::SEALContext context, const SEALBackend& backend,
                         double scale, bool galois_keys)
    : _internal_context(context),
      _backend(backend),
      _scale(std::pow(2, scale)),
      _gen_galois_keys(galois_keys),
      _keygen(context),
      _sec_key(_keygen.secret_key()) {
  _is_ckks = _internal_context.first_context_data()->parms().scheme() ==
             seal::scheme_type::ckks;
  _is_bfv = _internal_context.first_context_data()->parms().scheme() ==
            seal::scheme_type::bfv;
  if (is_bfv()) {
    _batchencoder = std::make_unique<seal::BatchEncoder>(_internal_context);
    _slot_count = _batchencoder->slot_count();
  }
  if (is_ckks()) {
    if (scale == -1) {
      throw std::invalid_argument("scale should be postive");
    }
    _ckksencoder = std::make_unique<seal::CKKSEncoder>(_internal_context);
    _slot_count = _ckksencoder->slot_count();
  }
  auto& params = _internal_context.first_context_data()->parms();
  std::stringstream ss;
  ss << "SEAL ";
  if (is_bfv()) {
    ss << "BFV context. poyl_modulus_degree " << params.poly_modulus_degree()
       << "; coeff_modolus bits ";
    coeff_modulus_to_stringstream(ss, params.coeff_modulus(), true);
    ss << "; plain_moduls bits " << params.plain_modulus().bit_count();
  } else if (is_ckks()) {
    ss << "CKKS context. poyl_modulus_degree " << params.poly_modulus_degree()
       << "; coeff_modolus bits ";
    coeff_modulus_to_stringstream(ss, params.coeff_modulus(), true);
    ss << "; scale " << _scale;
  } else {
    ss << "unknown scheme";
  }
  _string_representation = ss.str();

  // update the memory manager
  startNewGroup("default");
  memory_mode =
      std::getenv("ALUMINUM_SHARK_AGRESSIVE_MEMORY_CLEANUP") == nullptr
          ? -1
          : std::stoi(std::getenv("ALUMINUM_SHARK_AGRESSIVE_MEMORY_CLEANUP"));
};

bool SEALContext::is_ckks() const { return _is_ckks; }

bool SEALContext::is_bfv() const { return _is_bfv; }

// TODO: more verbose?
const std::string& SEALContext::to_string() const {
  return _string_representation;
}

const HEBackend* SEALContext::getBackend() const { return &_backend; }

int SEALContext::numberOfSlots() const { return _slot_count; }

const seal::Evaluator& SEALContext::evaluator() const { return *_evaluator; }
const seal::SEALContext& SEALContext::context() const {
  return _internal_context;
}
const seal::RelinKeys& SEALContext::relinKeys() const { return _relin_keys; }
const seal::GaloisKeys& SEALContext::galoisKeys() const { return _gal_keys; }
// Key management

// the pub key gets created together with the secret key. so we create all the
// nessecary structures like evalutor and such in this method
void SEALContext::createPublicKey() {
  _keygen.create_public_key(_pub_key);
  _keygen.create_relin_keys(_relin_keys);
  if (_gen_galois_keys) {
    _keygen.create_galois_keys(_gal_keys);
  }
  _encryptor = std::make_unique<seal::Encryptor>(_internal_context, _pub_key);
  _evaluator = std::make_unique<seal::Evaluator>(_internal_context);
  _pub_key_ready = true;
}

// SEAL requires the private key to be created first. the key generator
// automaticlaly generates the pubkey as well.
void SEALContext::createPrivateKey() {
  BACKEND_LOG << "generating secret key" << std::endl;
  // _sec_key = _keygen.secret_key();
  BACKEND_LOG << "Creating decryptor" << std::endl;
  _decryptor = std::make_unique<seal::Decryptor>(_internal_context, _sec_key);
  _sec_key_ready = true;
}

// save public key to file
void SEALContext::savePublicKey(const std::string& file) {
  BACKEND_LOG << "saving keys not implemented yet" << std::endl;
}
// save private key ot file
void SEALContext::savePrivateKey(const std::string& file) {
  BACKEND_LOG << "saving keys not implemented yet" << std::endl;
}

// load public key from file
void SEALContext::loadPublicKey(const std::string& file) {
  BACKEND_LOG << "loading keys not implemented yet" << std::endl;
}
// load private key from file
void SEALContext::loadPrivateKey(const std::string& file) {
  BACKEND_LOG << "loading keys not implemented yet" << std::endl;
}

// Ciphertext related

// encryption Functions
std::shared_ptr<HECtxt> SEALContext::encrypt(std::vector<long>& plain,
                                             const std::string name) const {
  std::shared_ptr<HEPtxt> ptxt = encode(plain);
  std::shared_ptr<HECtxt> ctxt_ptr = encrypt(ptxt, name);
  return ctxt_ptr;
}

std::shared_ptr<HECtxt> SEALContext::encrypt(std::vector<double>& plain,
                                             const std::string name) const {
  BACKEND_LOG << "encoding plaintext " << name << std::endl;
  std::shared_ptr<HEPtxt> ptxt =
      encode(plain);  // we own this memory now. need to delete it
#ifdef DEBUG_BUILD
  BACKEND_LOG << "scale " << ((std::dynamic_pointer_cast<SEALPtxt>(ptxt))->sealPlaintext().scale()
              << std::endl;
  std::vector<double> debug_vec = decodeDouble(ptxt);
  print_vector(debug_vec, 10);
#endif
  BACKEND_LOG << "encyrpting plaintext " << name << std::endl;
  std::shared_ptr<HECtxt> ctxt_ptr = encrypt(ptxt, name);
#ifdef DEBUG_BUILD
  debug_vec = decryptDouble(ctxt_ptr);
  print_vector(debug_vec, 10);
#endif
  return ctxt_ptr;
}

std::shared_ptr<HECtxt> SEALContext::encrypt(std::shared_ptr<HEPtxt> ptxt,
                                             const std::string name) const {
  std::shared_ptr<SEALPtxt> seal_ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(ptxt);
  std::shared_ptr<SEALCtxt> ctxt_ptr =
      std::make_shared<SEALCtxt>(name, seal_ptxt->content_type(), *this);
  _encryptor->encrypt(seal_ptxt->sealPlaintext(), ctxt_ptr->sealCiphertext(),
                      ctxt_ptr->sealCiphertext().pool());
  return ctxt_ptr;
}

// decryption functions
std::vector<long> SEALContext::decryptLong(std::shared_ptr<HECtxt> ctxt) const {
  std::shared_ptr<SEALCtxt> seal_ctxt =
      std::dynamic_pointer_cast<SEALCtxt>(ctxt);
  std::shared_ptr<SEALPtxt> result =
      std::make_shared<SEALPtxt>(seal::Plaintext(), CONTENT_TYPE::LONG, *this);
  _decryptor->decrypt(seal_ctxt->sealCiphertext(), result->sealPlaintext());
  return decodeLong(result);
}

std::vector<double> SEALContext::decryptDouble(
    std::shared_ptr<HECtxt> ctxt) const {
  std::shared_ptr<SEALCtxt> seal_ctxt =
      std::dynamic_pointer_cast<SEALCtxt>(ctxt);
  BACKEND_LOG << "decrypting " << std::endl;
  std::shared_ptr<SEALPtxt> result = std::make_shared<SEALPtxt>(
      seal::Plaintext(), CONTENT_TYPE::DOUBLE, *this);
  BACKEND_LOG << "created result plaintext. calling decyrption function "
              << std::endl;
  _decryptor->decrypt(seal_ctxt->sealCiphertext(), result->sealPlaintext());
  BACKEND_LOG << "decryption successful. decoding next" << std::endl;
  return decodeDouble(result);
}

// Plaintext related

// encoding
std::shared_ptr<HEPtxt> SEALContext::encode(
    const std::vector<long>& plain) const {
  std::shared_ptr<SEALPtxt> ptxt_ptr =
      std::make_shared<SEALPtxt>(seal::Plaintext(), CONTENT_TYPE::LONG, *this);
  if (is_ckks()) {
    std::vector<double> double_vec(plain.begin(), plain.end());
    return encode(double_vec);
  } else {
    // create plaintext
    if (plain.size() == 1) {
      _batchencoder->encode(std::vector<long>(plain[0], _slot_count),
                            ptxt_ptr->sealPlaintext());
    } else {
      _batchencoder->encode(plain, ptxt_ptr->sealPlaintext());
    }
    // check if all values are one or zero
    auto zero_one = all_zero_or_one(plain);
    ptxt_ptr->_allZero = zero_one.first;
    ptxt_ptr->_allOne = zero_one.second;
  }
  return ptxt_ptr;
}

std::shared_ptr<HEPtxt> SEALContext::encode(
    const std::vector<double>& plain) const {
  return encode(plain, _scale);
}

std::shared_ptr<HEPtxt> SEALContext::encode(const std::vector<long>& plain,
                                            double scale) const {
  return encode(plain, _internal_context.first_parms_id(), scale);
}

std::shared_ptr<HEPtxt> SEALContext::encode(const std::vector<double>& plain,
                                            double scale) const {
  return encode(plain, _internal_context.first_parms_id(), scale);
}

std::shared_ptr<HEPtxt> SEALContext::encode(const std::vector<long>& plain,
                                            seal::parms_id_type params_id,
                                            double scale) const {
  BACKEND_LOG << "encoding plaintext with scale " << scale << std::endl;
  std::shared_ptr<SEALPtxt> ptxt_ptr =
      std::make_shared<SEALPtxt>(seal::Plaintext(), CONTENT_TYPE::LONG, *this);
  if (is_ckks()) {
    std::vector<double> double_vec(plain.begin(), plain.end());
    return encode(double_vec, params_id, scale);
  } else {
    // create plaintext
    _batchencoder->encode(plain, ptxt_ptr->sealPlaintext());
    // check if all values are one or zero
    auto zero_one = all_zero_or_one(plain);
    ptxt_ptr->_allZero = zero_one.first;
    ptxt_ptr->_allOne = zero_one.second;
  }
  return ptxt_ptr;
}
std::shared_ptr<HEPtxt> SEALContext::encode(const std::vector<double>& plain,
                                            seal::parms_id_type params_id,
                                            double scale) const {
  BACKEND_LOG << "encoding plaintext with scale " << scale << std::endl;
#ifdef DEBUG_BUILD
  stream_vector(plain);
#endif
  std::shared_ptr<SEALPtxt> ptxt_ptr;
  if (memory_mode == -2) {
    ptxt_ptr = std::make_shared<SEALPtxt>(
        seal::Plaintext(seal::MemoryPoolHandle::New()), CONTENT_TYPE::DOUBLE,
        *this);
  } else {
    ptxt_ptr = std::make_shared<SEALPtxt>(seal::Plaintext(),
                                          CONTENT_TYPE::DOUBLE, *this);
  }

  if (plain.size() == 1) {
    _ckksencoder->encode(plain[0], params_id, scale, ptxt_ptr->sealPlaintext(),
                         ptxt_ptr->sealPlaintext().pool());
  } else {
    _ckksencoder->encode(plain, params_id, scale, ptxt_ptr->sealPlaintext(),
                         ptxt_ptr->sealPlaintext().pool());
  }
  // check if all values are one or zero
  auto zero_one = all_zero_or_one(plain);
  ptxt_ptr->_allZero = zero_one.first;
  ptxt_ptr->_allOne = zero_one.second;
  return ptxt_ptr;
}

void SEALContext::encode(SEALPtxt& ptxt, seal::parms_id_type params_id,
                         double scale) const {
  if (is_ckks()) {
    if (ptxt.double_values.size() == 1) {
      _ckksencoder->encode(ptxt.double_values[0], params_id, scale,
                           ptxt._internal_ptxt, ptxt.sealPlaintext().pool());
    } else {
      _ckksencoder->encode(ptxt.double_values, params_id, scale,
                           ptxt._internal_ptxt, ptxt.sealPlaintext().pool());
    }
  } else {
    if (ptxt.long_values.size() == 1) {
      _batchencoder->encode(std::vector<long>(ptxt.long_values[0], _slot_count),
                            ptxt._internal_ptxt);
    } else {
      _batchencoder->encode(ptxt.long_values, ptxt._internal_ptxt);
    }
  }
}

std::shared_ptr<HEPtxt> SEALContext::createPtxt(
    const std::vector<long>& vec) const {
  std::shared_ptr<SEALPtxt> ptxt;
  if (memory_mode == -2) {
    ptxt = std::make_shared<SEALPtxt>(
        seal::Plaintext(seal::MemoryPoolHandle::New()), CONTENT_TYPE::LONG,
        *this);
  } else {
    ptxt = std::make_shared<SEALPtxt>(seal::Plaintext(), CONTENT_TYPE::LONG,
                                      *this);
  }
  ptxt->long_values = vec;
  return ptxt;
}

std::shared_ptr<HEPtxt> SEALContext::createPtxt(
    const std::vector<double>& vec) const {
  std::shared_ptr<SEALPtxt> ptxt;
  if (memory_mode == -2) {
    ptxt = std::make_shared<SEALPtxt>(
        seal::Plaintext(seal::MemoryPoolHandle::New()), CONTENT_TYPE::DOUBLE,
        *this);
  } else {
    ptxt = std::make_shared<SEALPtxt>(seal::Plaintext(), CONTENT_TYPE::DOUBLE,
                                      *this);
  }

  ptxt->double_values = vec;
  return ptxt;
}

std::shared_ptr<HEPtxt> SEALContext::createPtxt(
    std::vector<double>&& vec) const {
  std::shared_ptr<SEALPtxt> ptxt;
  if (memory_mode == -2) {
    ptxt = std::make_shared<SEALPtxt>(
        seal::Plaintext(seal::MemoryPoolHandle::New()), CONTENT_TYPE::DOUBLE,
        *this);
  } else {
    ptxt = std::make_shared<SEALPtxt>(seal::Plaintext(), CONTENT_TYPE::DOUBLE,
                                      *this);
  }
  ptxt->double_values = vec;
  return ptxt;
}

HE_SCHEME SEALContext::scheme() const {
  BACKEND_LOG << "getting scheme type: "
              << (is_ckks() ? HE_SCHEME::CKKS : HE_SCHEME::BFV) << std::endl;
  return is_ckks() ? HE_SCHEME::CKKS : HE_SCHEME::BFV;
}

// decoding

// need to move the function definintion into the cpp file so we can use the
// incomplete type SEALPtxt
template <class T>
std::vector<T> SEALContext::decode(const SEALPtxt& ptxt) const {
  std::vector<T> result;
  _ckksencoder->decode(ptxt.sealPlaintext(), result);
  return result;
}

// since the definition is in the cpp we need to instantiate the use functions
// explicitly. this is not a problem since we know what types they will be
// used with.
template <>
std::vector<double> SEALContext::decode<double>(const SEALPtxt& ptxt) const {
  if (ptxt.double_values.size() != 0) {
    return ptxt.double_values;
  }
  std::vector<double> result;
  _ckksencoder->decode(ptxt.sealPlaintext(), result);
  return result;
}

// template specialization for the `long` decoding function
template <>
std::vector<long> SEALContext::decode<long>(const SEALPtxt& ptxt) const {
  std::vector<long> result;
  if (is_ckks()) {
    std::vector<double> double_vec;
    _ckksencoder->decode(ptxt.sealPlaintext(), double_vec);
    // need to the type to long
    result = std::vector<long>(double_vec.begin(), double_vec.end());
  } else if (is_bfv()) {
    _batchencoder->decode(ptxt.sealPlaintext(), result);
  } else {
    throw std::runtime_error("Unsupported scheme");
  }
  return result;
}

std::vector<long> SEALContext::decodeLong(std::shared_ptr<HEPtxt> ptxt) const {
  std::shared_ptr<SEALPtxt> seal_ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(ptxt);
  return decode<long>(*seal_ptxt);
}

std::vector<double> SEALContext::decodeDouble(
    std::shared_ptr<HEPtxt> ptxt) const {
  std::shared_ptr<SEALPtxt> seal_ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(ptxt);
  return decode<double>(*seal_ptxt);
}

// void create_new_memory_pool() {}

void SEALContext::startNewGroup(const std::string& name) const {
  update_memory_manager(name);
}

}  // namespace aluminum_shark