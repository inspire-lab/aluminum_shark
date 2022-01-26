import os

os.environ['ALUMINUM_SHARK_LOGGING'] = '1'
import aluminum_shark as shark

backend = shark.HEBackend(
    '/home/robert/workspace/aluminum_shark/seal_backend/aluminum_shark_seal.so')

context = backend.createContextCKKS(8192, [60, 40, 40, 60], 40)
context.create_keys()

ctxt = context.encrypt(list(range(context.n_slots)),
                       name="test ctxt",
                       dtype=float)
shark.set_ciphertexts(ctxt)
ptxt = context.decrypt_double(ctxt)
