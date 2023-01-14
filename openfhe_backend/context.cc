#include "context.h"

#include <stdlib.h>

#include <functional>
#include <memory>
#include <string>

#include "backend_logging.h"
#include "context.h"
#include "ctxt.h"
#include "ptxt.h"
#include "utils/utils.h"

namespace {

const std::string BACKEND_NAME = "OpenFHE Backend";
const std::string BACKEND_STRING = BACKEND_NAME;
// BACKEND_NAME + " using OpenFHE " + OpenFHEBackend();

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

bool OpenFHEContext::is_ckks() const { return _is_ckks; }

bool OpenFHEContext::is_bfv() const { return _is_bfv; }

const std::string& OpenFHEContext::to_string() const {
  return _string_representation;
}

const HEBackend* OpenFHEContext::getBackend() const { return &_backend; }

int OpenFHEContext::numberOfSlots() const { return _slot_count; }

// Key management

// the pub key gets created together with the secret key

void OpenFHEContext::createPublicKey() { _pub_key_ready = true; }

// create private and public key alongside the relin key

void OpenFHEContext::createPrivateKey() {
  AS_LOG_INFO << "generating key pair" << std::endl;
  auto keys = _internal_context->KeyGen();
  _pub_key = keys.publicKey;
  _sec_key = keys.secretKey;
  _sec_key_ready = true;
  AS_LOG_INFO << "generating relineraztion key" << std::endl;
  _internal_context->EvalMultKeyGen(_sec_key);
}

// save public key to file

void OpenFHEContext::savePublicKey(const std::string& file) {
  BACKEND_LOG << "saving keys not implemented yet" << std::endl;
}
// save private key ot file

void OpenFHEContext::savePrivateKey(const std::string& file) {
  BACKEND_LOG << "saving keys not implemented yet" << std::endl;
}

// load public key from file

void OpenFHEContext::loadPublicKey(const std::string& file) {
  BACKEND_LOG << "loading keys not implemented yet" << std::endl;
}
// load private key from file

void OpenFHEContext::loadPrivateKey(const std::string& file) {
  BACKEND_LOG << "loading keys not implemented yet" << std::endl;
}

// Ciphertext related

// encryption Functions

HECtxt* OpenFHEContext::encrypt(std::vector<long>& plain,
                                const std::string name) const {
  HEPtxt* ptxt = encode(plain);  // we own this memory now. need to delete it
  HECtxt* ctxt_ptr = encrypt(ptxt, name);
  delete ptxt;  // no longer need the plain text
  return ctxt_ptr;
}

HECtxt* OpenFHEContext::encrypt(std::vector<double>& plain,
                                const std::string name) const {
  HEPtxt* ptxt = encode(plain);  // we own this memory now. need to delete it
  HECtxt* ctxt_ptr = encrypt(ptxt, name);
  delete ptxt;  // no longer need the plain text
  return ctxt_ptr;
}

HECtxt* OpenFHEContext::encrypt(HEPtxt* ptxt, const std::string name) const {
  OpenFHEPtxt* ofhe_ptxt = dynamic_cast<OpenFHEPtxt*>(ptxt);
  OpenFHECtxt* ctxt_ptr = new OpenFHECtxt(
      _internal_context->Encrypt(_pub_key, ofhe_ptxt->openFHEPlaintext()), name,
      ofhe_ptxt->content_type(), *this);
  return ctxt_ptr;
}

// decryption functions

std::vector<long> OpenFHEContext::decryptLong(HECtxt* ctxt) const {
  OpenFHECtxt* ofhe_ctxt = dynamic_cast<OpenFHECtxt*>(ctxt);
  OpenFHEPtxt result(lbcrypto::Plaintext(), CONTENT_TYPE::LONG, *this);
  _internal_context->Decrypt(_sec_key, ofhe_ctxt->openFHECiphertext(),
                             &result.openFHEPlaintext());
  return decodeLong(&result);
}

std::vector<double> OpenFHEContext::decryptDouble(HECtxt* ctxt) const {
  OpenFHECtxt* ofhe_ctxt = dynamic_cast<OpenFHECtxt*>(ctxt);
  OpenFHEPtxt result(lbcrypto::Plaintext(), CONTENT_TYPE::DOUBLE, *this);
  _internal_context->Decrypt(_sec_key, ofhe_ctxt->openFHECiphertext(),
                             &result.openFHEPlaintext());
  return decodeDouble(&result);
}

// Plaintext related

// encoding

HEPtxt* OpenFHEContext::encode(const std::vector<long>& plain) const {
  if (is_ckks()) {
    std::vector<double> double_vec(plain.begin(), plain.end());
    return encode(double_vec);
  } else {
    return encode_internal(plain);
  }
}

HEPtxt* OpenFHEContext::encode(const std::vector<double>& plain) const {
  return encode_internal(plain);
}

HEPtxt* OpenFHEContext::encode_internal(const std::vector<long>& plain,
                                        size_t noiseScaleDeg,
                                        uint32_t level) const {
  // BACKEND_LOG << "encoding plaintext with scale " << scale << std::endl;
  if (is_ckks()) {
    std::vector<double> double_vec(plain.begin(), plain.end());
    return encode_internal(double_vec, noiseScaleDeg, level);
  }
  // create plaintext
  OpenFHEPtxt* ptxt_ptr = new OpenFHEPtxt(
      _internal_context->MakePackedPlaintext(plain, noiseScaleDeg, level),
      CONTENT_TYPE::LONG, *this);
  // check if all values are one or zero
  auto zero_one = all_zero_or_one(plain);
  ptxt_ptr->_allZero = zero_one.first;
  ptxt_ptr->_allOne = zero_one.second;

  return ptxt_ptr;
}

HEPtxt* OpenFHEContext::encode_internal(const std::vector<double>& plain,
                                        size_t noiseScaleDeg,
                                        uint32_t level) const {
  OpenFHEPtxt* ptxt_ptr = new OpenFHEPtxt(
      _internal_context->MakeCKKSPackedPlaintext(plain, noiseScaleDeg, level),
      CONTENT_TYPE::DOUBLE, *this);

  // check if all values are one or zero
  auto zero_one = all_zero_or_one(plain);
  ptxt_ptr->_allZero = zero_one.first;
  ptxt_ptr->_allOne = zero_one.second;
  return ptxt_ptr;
}

void OpenFHEContext::encode(OpenFHEPtxt& ptxt, size_t noiseScaleDeg,
                            uint32_t level) const {
  if (is_ckks()) {
    ptxt._internal_ptxt = _internal_context->MakeCKKSPackedPlaintext(
        ptxt.double_values, noiseScaleDeg, level);

  } else {
    ptxt._internal_ptxt = _internal_context->MakePackedPlaintext(
        ptxt.long_values, noiseScaleDeg, level);
  }
}

HEPtxt* OpenFHEContext::createPtxt(const std::vector<long>& vec) const {
  OpenFHEPtxt* ptxt =
      new OpenFHEPtxt(lbcrypto::Plaintext(), CONTENT_TYPE::LONG, *this);
  ptxt->long_values = vec;
  return ptxt;
}

HEPtxt* OpenFHEContext::createPtxt(const std::vector<double>& vec) const {
  OpenFHEPtxt* ptxt;
  if (vec.size() == 1) {
    std::vector<double> temp(_slot_count, vec[0]);
    ptxt = new OpenFHEPtxt(_internal_context->MakeCKKSPackedPlaintext(temp),
                           CONTENT_TYPE::DOUBLE, *this);
    ptxt->double_values = temp;
  } else {
    ptxt = new OpenFHEPtxt(_internal_context->MakeCKKSPackedPlaintext(vec),
                           CONTENT_TYPE::DOUBLE, *this);
    ptxt->double_values = vec;
  }
  return ptxt;
}

HE_SCHEME OpenFHEContext::scheme() const {
  AS_LOG_DEBUG << "getting scheme type: "
               << (is_ckks() ? HE_SCHEME::CKKS : HE_SCHEME::BFV) << std::endl;
  return is_ckks() ? HE_SCHEME::CKKS : HE_SCHEME::BFV;
}

std::vector<long> OpenFHEContext::decodeLong(HEPtxt* ptxt) const {
  OpenFHEPtxt* ofhe_ptxt = dynamic_cast<OpenFHEPtxt*>(ptxt);
  std::vector<long> result;
  if (is_ckks()) {
    std::vector<double> double_vec = decodeDouble(ptxt);
    // need to the type to long
    result = std::vector<long>(double_vec.begin(), double_vec.end());
  } else if (is_bfv()) {
    result = ofhe_ptxt->openFHEPlaintext()->GetPackedValue();
  } else {
    throw std::runtime_error("Unsupported scheme");
  }
  return result;
}

std::vector<double> OpenFHEContext::decodeDouble(HEPtxt* ptxt) const {
  OpenFHEPtxt* ofhe_ptxt = dynamic_cast<OpenFHEPtxt*>(ptxt);
  if (ofhe_ptxt->double_values.size() != 0) {
    return ofhe_ptxt->double_values;
  }
  return ofhe_ptxt->openFHEPlaintext()->GetRealPackedValue();
}

}  // namespace aluminum_shark
