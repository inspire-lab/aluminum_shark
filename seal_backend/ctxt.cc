#include "ctxt.h"

#include <cxxabi.h>

#include <sstream>
#include <typeinfo>

#include "logging.h"
#include "object_count.h"
#include "ptxt.h"
#include "utils.h"
#include "utils/macros.h"

namespace {
const int64_t agressive_memory_cleanup =
    std::getenv("ALUMINUM_SHARK_AGRESSIVE_MEMORY_CLEANUP") == nullptr
        ? -1
        : std::stoi(std::getenv("ALUMINUM_SHARK_AGRESSIVE_MEMORY_CLEANUP"));
// counter for ciphertext instances. when it reaches a threshold of
// agressive_memory_cleanup we start a new group of ciphertexts. we might loose
// a few counting operations due to multithreading but this is more of a
// guideline
int64_t instance_counter = 0;
std::mutex memory_cleaunp_mutex;
}  // namespace

namespace aluminum_shark {

SEALCtxt::SEALCtxt(const std::string& name, CONTENT_TYPE content_type,
                   const SEALContext& context)
    : SEALCtxt(seal::Ciphertext(), name, content_type, context){};

SEALCtxt::SEALCtxt(seal::Ciphertext ctxt, const std::string& name,
                   CONTENT_TYPE content_type, const SEALContext& context)
    : _name(name),
      _content_type(content_type),
      _context(context),
      _internal_ctxt(ctxt) {
  count_ctxt(1);
  if (agressive_memory_cleanup != 1) {
    // check if we reached the threshold
    if (instance_counter > agressive_memory_cleanup) {
      // grab the lock and start the cleanup process
      const std::lock_guard<std::mutex> lock(memory_cleaunp_mutex);
      // first we check if another thread changed the count and we actually
      // still need to do the cleanup
      if (instance_counter > agressive_memory_cleanup) {
        // start a new group and reset the counter
        context.startNewGroup("_internal_");
        instance_counter = 0;
      }
    } else {
      ++instance_counter;
    }
  }
};

const seal::Ciphertext& SEALCtxt::sealCiphertext() const {
  return _internal_ctxt;
}
seal::Ciphertext& SEALCtxt::sealCiphertext() { return _internal_ctxt; }

CONTENT_TYPE SEALCtxt::content_type() const { return _content_type; }

const std::string& SEALCtxt::name() const { return _name; }

// TODO: more info
std::string SEALCtxt::to_string() const {
  std::stringstream ss;
  ss << "SEAL Ctxt: " << _name << "scale " << _internal_ctxt.scale();
  return ss.str();
}

const HEContext* SEALCtxt::getContext() const { return &_context; }

std::shared_ptr<HECtxt> SEALCtxt::deepCopy() {
  // work around since the copy constructor is private
  SEALCtxt* raw = new SEALCtxt(*this);
  std::shared_ptr<SEALCtxt> result = std::shared_ptr<SEALCtxt>(raw);
  std::stringstream ss;
  ss << "this " << static_cast<void*>(this) << " copy "
     << static_cast<void*>(result.get()) << std::endl;
  AS_LOG_DEBUG << ss.str();
  return result;
}

// returns the size of the ciphertext in bytes
size_t SEALCtxt::size() {
  // see: https://github.com/microsoft/SEAL/issues/88#issuecomment-564342477
  auto context_data =
      _context._internal_context.get_context_data(_internal_ctxt.parms_id());
  size_t size = _internal_ctxt.size();
  size *= context_data->parms().coeff_modulus().size();
  size *= context_data->parms().poly_modulus_degree();
  size *= 8;
  return size;
}

// arithmetic operations

// ctxt and ctxt

// Addintion

void SEALCtxt::match_scale_and_parms(const SEALCtxt& other) {
  const seal::SEALContext& seal_context = _context.context();
  // do we need to match scales?
  seal::Ciphertext& this_ctxt = _internal_ctxt;
  const seal::Ciphertext& other_ctxt = other.sealCiphertext();
  if (this_ctxt.scale() != other_ctxt.scale()) {
    // calculate scale
    double last_prime =
        static_cast<double>(seal_context.get_context_data(this_ctxt.parms_id())
                                ->parms()
                                .coeff_modulus()
                                .back()
                                .value());

    double temp_scale = other_ctxt.scale() / this_ctxt.scale() * last_prime;
    // create temporary plaintext
    seal::Plaintext plaintext =
        std::dynamic_pointer_cast<SEALPtxt>(
            _context.encode(std::vector<double>{1.}, this_ctxt.parms_id(),
                            temp_scale))
            ->sealPlaintext();
    _context._evaluator->multiply_plain_inplace(_internal_ctxt, plaintext);
    count_ctxt_ptxt_mult();
    _context._evaluator->relinearize_inplace(_internal_ctxt,
                                             _context.relinKeys());
    _context._evaluator->rescale_to_next_inplace(_internal_ctxt);
  }
  // check if the params id match now
  if (seal_context.get_context_data(_internal_ctxt.parms_id())->chain_index() ==
      seal_context.get_context_data(other_ctxt.parms_id())->chain_index()) {
    return;
  }
  _context._evaluator->mod_switch_to_inplace(_internal_ctxt,
                                             other_ctxt.parms_id());
}

std::shared_ptr<HECtxt> SEALCtxt::operator+(
    const std::shared_ptr<HECtxt> other) {
  const std::shared_ptr<SEALCtxt> other_ctxt =
      std::dynamic_pointer_cast<SEALCtxt>(other);
  std::shared_ptr<SEALCtxt> result = std::make_shared<SEALCtxt>(
      _name + " + " + other_ctxt->name(), _content_type, _context);
  try {
    _context._evaluator->add(_internal_ctxt, other_ctxt->sealCiphertext(),
                             result->sealCiphertext());
    count_ctxt_ctxt_add();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, other_ctxt->sealCiphertext(),
                        "operator+(std::shared_ptr<HECtxt>)", __FILE__,
                        __LINE__, &e);
    throw;
  }
  std::stringstream ss;
  ss << "ctxt + ctxt this " << (void*)this << " other " << other << " result "
     << result << std::endl;
  return result;
}

void SEALCtxt::addInPlace(const std::shared_ptr<HECtxt> other) {
  const std::shared_ptr<SEALCtxt> other_ctxt =
      std::dynamic_pointer_cast<SEALCtxt>(other);
  try {
    AS_LOG_DEBUG << "adding. lhs scale " << std::log2(_internal_ctxt.scale())
                 << " rhs scale "
                 << std::log2(other_ctxt->sealCiphertext().scale())
                 << std::endl;
    AS_LOG_DEBUG << "\t lhs params index: "
                 << _context._internal_context
                        .get_context_data(_internal_ctxt.parms_id())
                        ->chain_index()
                 << " \n\t rhs params index "
                 << _context._internal_context
                        .get_context_data(
                            other_ctxt->sealCiphertext().parms_id())
                        ->chain_index()
                 << std::endl;
    std::stringstream ss;
    ss << " ctxt += ctxt  this " << static_cast<void*>(this) << " other "
       << other << std::endl;
    ss << "adding. lhs scale " << std::log2(_internal_ctxt.scale())
       << " rhs scale " << std::log2(other_ctxt->sealCiphertext().scale())
       << std::endl;
    ss << "\t lhs params index: "
       << _context._internal_context
              .get_context_data(_internal_ctxt.parms_id())
              ->chain_index()
       << " \n\t rhs params index "
       << _context._internal_context
              .get_context_data(other_ctxt->sealCiphertext().parms_id())
              ->chain_index()
       << std::endl;
    AS_LOG_DEBUG << ss.str();
    // params id are mismatch we need to bring them to the same parameters
    if (_internal_ctxt.parms_id() != other_ctxt->sealCiphertext().parms_id()) {
      auto context_data_lhs = _context._internal_context.get_context_data(
          _internal_ctxt.parms_id());
      auto context_data_rhs = _context._internal_context.get_context_data(
          other_ctxt->sealCiphertext().parms_id());
      // other has a higher modulus. need to scale it down
      if (context_data_lhs->chain_index() < context_data_rhs->chain_index()) {
        std::stringstream ss;
        ss << "parameters mismatch. rescaling other. scales lhs "
           << _internal_ctxt.scale() << " lhs "
           << other_ctxt->sealCiphertext().scale() << std::endl;
        AS_LOG_DEBUG << ss.str();

        auto rescaled_ctxt =
            std::dynamic_pointer_cast<SEALCtxt>(other_ctxt->deepCopy());
        rescaled_ctxt->match_scale_and_parms(*this);
        ss << "after scale matching rhs " << _internal_ctxt.scale() << " lhs "
           << rescaled_ctxt->sealCiphertext().scale()
           << "\n\t lhs params index: "
           << _context._internal_context
                  .get_context_data(_internal_ctxt.parms_id())
                  ->chain_index()
           << " parms_id: [ ";
        for (auto i : _internal_ctxt.parms_id()) {
          ss << i << ", ";
        }
        ss << "] \n\t rhs params index "
           << _context._internal_context
                  .get_context_data(rescaled_ctxt->sealCiphertext().parms_id())
                  ->chain_index()
           << "parms_id: [ ";
        for (auto i : rescaled_ctxt->sealCiphertext().parms_id()) {
          ss << i << ", ";
        }
        ss << "]" << std::endl;

        AS_LOG_DEBUG << ss.str();

        _context._evaluator->add_inplace(_internal_ctxt,
                                         rescaled_ctxt->sealCiphertext());
      } else {
        // this has a higher moduls
        match_scale_and_parms(*other_ctxt);
        _context._evaluator->add_inplace(_internal_ctxt,
                                         other_ctxt->sealCiphertext());
      }
    } else {
      // scales and everything match. just add
      _context._evaluator->add_inplace(_internal_ctxt,
                                       other_ctxt->sealCiphertext());
    }
    count_ctxt_ctxt_add();
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    logComputationError(_internal_ctxt, other_ctxt->sealCiphertext(),
                        "addInplace(std::shared_ptr<HECtxt>)", __FILE__,
                        __LINE__, &e, &_context._internal_context);
    throw;
  }
}

// subtraction
std::shared_ptr<HECtxt> SEALCtxt::operator-(
    const std::shared_ptr<HECtxt> other) {
  const std::shared_ptr<SEALCtxt> other_ctxt =
      std::dynamic_pointer_cast<SEALCtxt>(other);
  std::shared_ptr<SEALCtxt> result = std::make_shared<SEALCtxt>(
      _name + " * " + other_ctxt->name(), _content_type, _context);
  try {
    _context._evaluator->sub(_internal_ctxt, other_ctxt->sealCiphertext(),
                             result->sealCiphertext());
    count_ctxt_ctxt_add();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, other_ctxt->sealCiphertext(),
                        "operator-(std::shared_ptr<HECtxt>)", __FILE__,
                        __LINE__, &e);
    throw;
  }

  return result;
}

void SEALCtxt::subInPlace(const std::shared_ptr<HECtxt> other) {
  const std::shared_ptr<SEALCtxt> other_ctxt =
      std::dynamic_pointer_cast<SEALCtxt>(other);
  try {
    _context._evaluator->sub_inplace(_internal_ctxt,
                                     other_ctxt->sealCiphertext());
    count_ctxt_ctxt_add();

  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, other_ctxt->sealCiphertext(),
                        "subInPlace(std::shared_ptr<HECtxt>)", __FILE__,
                        __LINE__, &e);
    throw;
  }
}

// multiplication

std::shared_ptr<HECtxt> SEALCtxt::operator*(
    const std::shared_ptr<HECtxt> other) {
  const std::shared_ptr<SEALCtxt> other_ctxt =
      std::dynamic_pointer_cast<SEALCtxt>(other);

  std::shared_ptr<SEALCtxt> result = std::make_shared<SEALCtxt>(
      _name + " * " + other_ctxt->name(), _content_type, _context);
  try {
    _context._evaluator->multiply(_internal_ctxt, other_ctxt->sealCiphertext(),
                                  result->sealCiphertext());
    _context._evaluator->relinearize_inplace(result->sealCiphertext(),
                                             _context.relinKeys());
    _context._evaluator->rescale_to_next_inplace(result->sealCiphertext());
    count_ctxt_ctxt_mult();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, other_ctxt->sealCiphertext(),
                        "operatir*(std::shared_ptr<HECtxt>)", __FILE__,
                        __LINE__, &e);
    throw;
  }
  return result;
}

void mult_check(seal::Ciphertext& one, seal::Ciphertext& two,
                const SEALContext& context) {
  // check if the resulting multiplication will be within scale
  double max_scale = context.context()
                         .get_context_data(one.parms_id())
                         ->total_coeff_modulus_bit_count();

  while (std::log2(one.scale() * two.scale()) > max_scale) {
    std::stringstream ss;
    ss << "rescaling from: " << one.scale() << " chain_index: "
       << context.context().get_context_data(one.parms_id())->chain_index()
       << std::endl;
    AS_LOG_DEBUG << ss.str();
    context.evaluator().rescale_to_next_inplace(one);
    context.evaluator().rescale_to_next_inplace(two);
    max_scale = context.context()
                    .get_context_data(one.parms_id())
                    ->total_coeff_modulus_bit_count();
    ss << "rescaled to: " << one.scale() << " chain_index: "
       << context.context().get_context_data(one.parms_id())->chain_index()
       << std::endl;
    AS_LOG_DEBUG << ss.str();
  }
}

void SEALCtxt::multInPlace(const std::shared_ptr<HECtxt> other) {
  const std::shared_ptr<SEALCtxt> other_ctxt =
      std::dynamic_pointer_cast<SEALCtxt>(other);
  try {
    std::stringstream ss;
    ss << "ctxt *= ctxt this " << (void*)this << " other " << other
       << std::endl;
    AS_LOG_DEBUG << ss.str();
    auto& lhs_parms = _internal_ctxt.parms_id();
    auto& rhs_parms = other_ctxt->sealCiphertext().parms_id();
    if (lhs_parms != rhs_parms) {
      seal::Ciphertext ctxt;
      auto& s_context = _context._internal_context;
      // mod switch this
      if (s_context.get_context_data(lhs_parms)->chain_index() >
          s_context.get_context_data(rhs_parms)->chain_index()) {
        AS_LOG_DEBUG << "modswitching `this` from " +
                            std::to_string(_internal_ctxt.scale())
                     << std::endl;
        _context._evaluator->mod_switch_to_inplace(_internal_ctxt, rhs_parms);
        AS_LOG_DEBUG << "modswitched `this` to " +
                            std::to_string(_internal_ctxt.scale())
                     << std::endl;
        _context._evaluator->multiply_inplace(_internal_ctxt,
                                              other_ctxt->sealCiphertext());
      } else {  // mod switch other
        ctxt = other_ctxt->sealCiphertext();
        AS_LOG_DEBUG << "modswitching `other` from " +
                            std::to_string(ctxt.scale())
                     << std::endl;
        _context._evaluator->mod_switch_to_inplace(ctxt, lhs_parms);
        AS_LOG_DEBUG << "modswitching `other` to " +
                            std::to_string(ctxt.scale())
                     << std::endl;
        _context._evaluator->multiply_inplace(_internal_ctxt, ctxt);
      }
    } else {
      _context._evaluator->multiply_inplace(_internal_ctxt,
                                            other_ctxt->sealCiphertext());
    }
    _context._evaluator->relinearize_inplace(_internal_ctxt,
                                             _context.relinKeys());
    _context._evaluator->rescale_to_next_inplace(_internal_ctxt);
    count_ctxt_ctxt_mult();

  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, other_ctxt->sealCiphertext(),
                        "multInPlace(std::shared_ptr<HECtxt>)", __FILE__,
                        __LINE__, &e, &_context._internal_context);
    throw;
  }
}

// ctxt and plain

// addition
std::shared_ptr<HECtxt> SEALCtxt::operator+(std::shared_ptr<HEPtxt> other) {
  std::shared_ptr<SEALPtxt> ptxt = std::dynamic_pointer_cast<SEALPtxt>(other);

  std::shared_ptr<SEALCtxt> result = std::make_shared<SEALCtxt>(
      _name + " + plaintext", _content_type, _context);
  SEALPtxt rescaled = ptxt->scaleToMatch(*this);
  try {
    _context._evaluator->add_plain(_internal_ctxt, rescaled.sealPlaintext(),
                                   result->sealCiphertext());
    count_ctxt_ptxt_add();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, rescaled.sealPlaintext(),
                        "opertator+(std::shared_ptr<HEPtxt>)", __FILE__,
                        __LINE__, &e);
    throw;
  }
  std::stringstream ss;
  ss << "ctxt + ptxt this " << (void*)this << " result " << result << std::endl;
  AS_LOG_DEBUG << ss.str();
  return result;
}

void SEALCtxt::addInPlace(std::shared_ptr<HEPtxt> other) {
  std::shared_ptr<SEALPtxt> ptxt = std::dynamic_pointer_cast<SEALPtxt>(other);
  SEALPtxt rescaled = ptxt->scaleToMatch(*this);

  std::stringstream ss;
  ss << "ctxt += ptxt this " << (void*)this << std::endl;
  AS_LOG_DEBUG << ss.str();
  try {
    _context._evaluator->add_plain_inplace(_internal_ctxt,
                                           rescaled.sealPlaintext());
    count_ctxt_ptxt_add();
  } catch (const std::exception& e) {
    double scale_factor = std::max<double>(
        {std::fabs(_internal_ctxt.scale()),
         std::fabs(rescaled.sealPlaintext().scale()), double{1.0}});
    bool are_close =
        std::fabs(_internal_ctxt.scale() - rescaled.sealPlaintext().scale()) <
        epsilon<double> * scale_factor;
    BACKEND_LOG << "scales equal: "
                << std::to_string(_internal_ctxt.scale() ==
                                  rescaled.sealPlaintext().scale())
                << " scale difference: "
                << std::to_string(std::fabs(_internal_ctxt.scale() -
                                            rescaled.sealPlaintext().scale()))
                << " are close: " << are_close << std::endl;
    logComputationError(_internal_ctxt, rescaled.sealPlaintext(),
                        "addInPlace(std::shared_ptr<HEPtxt>)", __FILE__,
                        __LINE__, &e);
    throw;
  }
}

// subtraction
std::shared_ptr<HECtxt> SEALCtxt::operator-(std::shared_ptr<HEPtxt> other) {
  const std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(other);
  std::shared_ptr<SEALCtxt> result = std::make_shared<SEALCtxt>(
      _name + " + plaintext", _content_type, _context);
  SEALPtxt rescaled = ptxt->scaleToMatch(*this);
  try {
    _context._evaluator->sub_plain(_internal_ctxt, rescaled.sealPlaintext(),
                                   result->sealCiphertext());
    count_ctxt_ptxt_add();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, rescaled.sealPlaintext(),
                        "operator-(std::shared_ptr<HEPtxt>)", __FILE__,
                        __LINE__, &e);
    throw;
  }
  return result;
}

void SEALCtxt::subInPlace(std::shared_ptr<HEPtxt> other) {
  const std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(other);
  SEALPtxt rescaled = ptxt->rescale(_internal_ctxt.scale());
  try {
    _context._evaluator->sub_plain_inplace(_internal_ctxt,
                                           rescaled.sealPlaintext());
    count_ctxt_ptxt_add();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, rescaled.sealPlaintext(),
                        "subInplace-(std::shared_ptr<HEPtxt>)", __FILE__,
                        __LINE__, &e);
    throw;
  }
}

// multiplication
std::shared_ptr<HECtxt> SEALCtxt::operator*(std::shared_ptr<HEPtxt> other) {
  std::shared_ptr<SEALPtxt> ptxt = std::dynamic_pointer_cast<SEALPtxt>(other);
  // if (ptxt->isAllZero()) {
  //   // if we multiplied here the scale would the ciphertext scale *
  //   plainscale
  //   // butt since we specifically rescale the plaintext to be the same
  //   scale
  //   // as the ciphertext we can just square the scale and for rescaling the
  //   // the plaintext before encryption
  //   // TODO: be smarter about the scale. we should really look at the scale
  //   and
  //   // what the next scale down would lead to and use that scale during
  //   encoding BACKEND_LOG << "circumventing transparent ciphertext" <<
  //   std::endl; SEALPtxt temp = ptxt->rescale(
  //       this->_internal_ctxt.scale() * this->_internal_ctxt.scale(),
  //       _internal_ctxt.parms_id());
  //   std::shared_ptr<SEALCtxt> res =
  //   static_cast<std::shared_ptr<SEALCtxt((_context.encrypt(&temp));
  //   res->_name = _name + " * plaintext";
  //   _context._evaluator->relinearize_inplace(res->sealCiphertext(),
  //                                            _context.relinKeys());
  //   _context._evaluator->rescale_to_next_inplace(res->sealCiphertext());
  //   return res;
  // }

  // TODO: shortcut evalution for special case 1
  ptxt->mutex.lock();
  if (!are_close(_internal_ctxt.scale(), ptxt->sealPlaintext().scale())) {
    ptxt->scaleToMatchInPlace(*this);
  }
  ptxt->mutex.unlock();
  BACKEND_LOG << "creating result ctxt" << std::endl;
  std::shared_ptr<SEALCtxt> result = std::make_shared<SEALCtxt>(
      _name + " * plaintext", _content_type, _context);
  try {
    BACKEND_LOG << "running multiplication" << std::endl;
    _context._evaluator->multiply_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                        result->sealCiphertext());
    BACKEND_LOG << "running relin" << std::endl;
    _context._evaluator->relinearize_inplace(result->sealCiphertext(),
                                             _context.relinKeys());
    BACKEND_LOG << "running rescale" << std::endl;
    _context._evaluator->rescale_to_next_inplace(result->sealCiphertext());
    count_ctxt_ptxt_mult();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "operator*(std::shared_ptr<HEPtxt>)", __FILE__,
                        __LINE__, &e);
    throw;
  }

  BACKEND_LOG << "mutlplication done" << std::endl;
  std::stringstream ss;
  ss << "ctxt * ptxt this: " << (void*)this << " result " << result
     << std::endl;
  AS_LOG_DEBUG << ss.str();
  return result;
}

void SEALCtxt::multInPlace(std::shared_ptr<HEPtxt> other) {
  const std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(other);
  // if (ptxt->isAllZero()) {
  //   // if we multiplied here the scale would the ciphertext scale *
  //   plainscale
  //   // butt since we specifically rescale the plaintext to be the same scale
  //   // as the ciphertext we can just square the scale and for rescaling the
  //   // the plaintext before encryption
  //   // TODO: same as operator*(std::shared_ptr<HEPtxt>). use the proper scale
  //   // during encoding
  //   std::shared_ptr<SEALPtxt> temp = std::make_shared<SEALPtxt>(
  //       std::move(ptxt->rescale(std::log2(this->_internal_ctxt.scale() *
  //                                         this->_internal_ctxt.scale()),
  //                               _internal_ctxt.parms_id())));

  //   std::shared_ptr<SEALCtxt> res =
  //       std::dynamic_pointer_cast<SEALCtxt>(_context.encrypt(temp));
  //   res->_name = _name + " * plaintext";
  //   _internal_ctxt = res->sealCiphertext();
  //   _context._evaluator->relinearize_inplace(_internal_ctxt,
  //                                            _context.relinKeys());
  //   _context._evaluator->rescale_to_next_inplace(_internal_ctxt);
  // }

  SEALPtxt rescaled = ptxt->scaleToMatch(*this);
  try {
    _context._evaluator->multiply_plain_inplace(_internal_ctxt,
                                                rescaled.sealPlaintext());
    _context._evaluator->relinearize_inplace(_internal_ctxt,
                                             _context.relinKeys());
    _context._evaluator->rescale_to_next_inplace(_internal_ctxt);
    std::stringstream ss;

    ss << "ctxt *= ptxt. this: " << (void*)this << "\n\tresult scale "
       << std::log2(_internal_ctxt.scale()) << std::endl;
    ss << "\t params index: "
       << _context._internal_context
              .get_context_data(_internal_ctxt.parms_id())
              ->chain_index()
       << std::endl;
    AS_LOG_DEBUG << ss.str();
    count_ctxt_ptxt_mult();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, rescaled.sealPlaintext(),
                        "multInPlace(std::shared_ptr<HEPtxt>)", __FILE__,
                        __LINE__, &e, &_context._internal_context);
    throw;
  }
}

// scalar ops

std::shared_ptr<HECtxt> SEALCtxt::operator*(long other) {
  std::shared_ptr<SEALCtxt> result = std::make_shared<SEALCtxt>(
      _name + " * " + std::to_string(other), _content_type, _context);
  std::vector<long> vec(_context.numberOfSlots(), other);
  std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(_context.encode(vec));
  result->multInPlace(ptxt);
  count_ctxt_ptxt_mult();
  return result;
}

void SEALCtxt::multInPlace(long other) {
  std::vector<long> vec(_context.numberOfSlots(), other);
  std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(_context.encode(vec));
  multInPlace(ptxt);
  count_ctxt_ptxt_mult();
}

std::shared_ptr<HECtxt> SEALCtxt::operator*(double other) {
  std::shared_ptr<SEALCtxt> result = std::make_shared<SEALCtxt>(
      _name + " * " + std::to_string(other), _content_type, _context);
  std::vector<double> vec(_context.numberOfSlots(), other);
  std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(_context.encode(vec));
  result->multInPlace(ptxt);
  count_ctxt_ptxt_mult();
  return result;
}

void SEALCtxt::multInPlace(double other) {
  std::vector<long> vec(_context.numberOfSlots(), other);
  std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(_context.encode(vec));
  multInPlace(ptxt);
}

std::shared_ptr<HECtxt> SEALCtxt::operator-(long other) {
  std::shared_ptr<SEALCtxt> result = std::make_shared<SEALCtxt>(
      _name + " + " + std::to_string(other), _content_type, _context);
  std::vector<long> vec(_context.numberOfSlots(), other);
  std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(_context.encode(vec));
  try {
    _context._evaluator->sub_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                   result->sealCiphertext());
    count_ctxt_ptxt_add();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "operator-(long)", __FILE__, __LINE__, &e);
    throw;
  }

  return result;
}

void SEALCtxt::subInPlace(long other) {
  std::vector<long> vec(_context.numberOfSlots(), other);
  std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(_context.encode(vec));
  try {
    _context._evaluator->sub_plain_inplace(_internal_ctxt,
                                           ptxt->sealPlaintext());
    count_ctxt_ptxt_add();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "subInPlace(long)", __FILE__, __LINE__, &e);
    throw;
  }
}

std::shared_ptr<HECtxt> SEALCtxt::operator-(double other) {
  std::shared_ptr<SEALCtxt> result = std::make_shared<SEALCtxt>(
      _name + " + " + std::to_string(other), _content_type, _context);
  std::vector<double> vec(_context.numberOfSlots(), other);
  std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(_context.encode(vec));
  try {
    _context._evaluator->sub_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                   result->sealCiphertext());
    count_ctxt_ptxt_add();

  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "operator-(double)", __FILE__, __LINE__, &e);
    throw;
  }

  return result;
}

void SEALCtxt::subInPlace(double other) {
  std::vector<double> vec(_context.numberOfSlots(), other);
  std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(_context.encode(vec));
  try {
    _context._evaluator->sub_plain_inplace(_internal_ctxt,
                                           ptxt->sealPlaintext());
    count_ctxt_ptxt_add();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "subInPlace(double)", __FILE__, __LINE__, &e);
    throw;
  }
}

std::shared_ptr<HECtxt> SEALCtxt::operator+(long other) {
  std::shared_ptr<SEALCtxt> result = std::make_shared<SEALCtxt>(
      _name + " + " + std::to_string(other), _content_type, _context);
  std::vector<long> vec(_context.numberOfSlots(), other);
  std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(_context.encode(vec));
  try {
    _context._evaluator->add_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                   result->sealCiphertext());
    count_ctxt_ptxt_add();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "opertator+(long)", __FILE__, __LINE__, &e);
    throw;
  }
  return result;
}

void SEALCtxt::addInPlace(long other) {
  std::vector<long> vec(_context.numberOfSlots(), other);
  std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(_context.encode(vec));
  try {
    _context._evaluator->add_plain_inplace(_internal_ctxt,
                                           ptxt->sealPlaintext());
    count_ctxt_ptxt_add();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "addInPlace(long)", __FILE__, __LINE__, &e);
    throw;
  }
}

std::shared_ptr<HECtxt> SEALCtxt::operator+(double other) {
  std::shared_ptr<SEALCtxt> result = std::make_shared<SEALCtxt>(
      _name + " + " + std::to_string(other), _content_type, _context);
  std::vector<double> vec(_context.numberOfSlots(), other);
  std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(_context.encode(vec));
  try {
    _context._evaluator->add_plain(_internal_ctxt, ptxt->sealPlaintext(),
                                   result->sealCiphertext());
    count_ctxt_ptxt_add();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "operator+(double)", __FILE__, __LINE__, &e);
    throw;
  }
  return result;
}

void SEALCtxt::addInPlace(double other) {
  std::vector<double> vec(_context.numberOfSlots(), other);
  std::shared_ptr<SEALPtxt> ptxt =
      std::dynamic_pointer_cast<SEALPtxt>(_context.encode(vec));
  try {
    _context._evaluator->add_plain_inplace(_internal_ctxt,
                                           ptxt->sealPlaintext());
    count_ctxt_ptxt_add();
  } catch (const std::exception& e) {
    logComputationError(_internal_ctxt, ptxt->sealPlaintext(),
                        "addInPlace(double)", __FILE__, __LINE__, &e);
    throw;
  }
}

// Rotation
void SEALCtxt::rotInPlace(int steps) {
  _context._evaluator->rotate_vector_inplace(_internal_ctxt, steps,
                                             _context._gal_keys);
  count_ctxt_rot();
}

std::shared_ptr<HECtxt> SEALCtxt::rotate(int steps) {
  std::shared_ptr<HECtxt> copy = this->deepCopy();
  copy->rotInPlace(steps);
  return copy;
}

// static ressource looging code
bool SEALCtxt::count_ops = false;

// ctxt x ctx
std::atomic_ulong SEALCtxt::mult_ctxt_count = 0;
// ctxt x ptx
std::atomic_ulong SEALCtxt::mult_ptxt_count = 0;

// ctxt x ctx
std::atomic_ulong SEALCtxt::add_ctxt_count = 0;
// ctxt x ptx
std::atomic_ulong SEALCtxt::add_ptxt_count = 0;

std::atomic_ulong SEALCtxt::rot_count = 0;

// resource logging
void SEALCtxt::count_ctxt_ctxt_mult() {
  if (LIKELY_FALSE(count_ops)) {
    ++mult_ctxt_count;
  }
}

void SEALCtxt::count_ctxt_ptxt_mult() {
  if (LIKELY_FALSE(count_ops)) {
    ++mult_ptxt_count;
  }
}

void SEALCtxt::count_ctxt_ctxt_add() {
  if (LIKELY_FALSE(count_ops)) {
    ++add_ctxt_count;
  }
}

void SEALCtxt::count_ctxt_ptxt_add() {
  if (LIKELY_FALSE(count_ops)) {
    ++add_ptxt_count;
  }
}

void SEALCtxt::count_ctxt_rot() {
  if (LIKELY_FALSE(count_ops)) {
    ++rot_count;
  }
}

}  // namespace aluminum_shark