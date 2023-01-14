#ifndef ALUMINUM_SHARK_COMMON_OBJECT_COUNT_H
#define ALUMINUM_SHARK_COMMON_OBJECT_COUNT_H

namespace aluminum_shark {

extern const bool AS_OBJECT_COUNT;

// object counting
void count_ptxt(int count);
void count_ctxt(int count);
int get_ptxt_count();
int get_ctxt_count();

int get_max_ptxt_count();
int get_max_ctxt_count();

int get_ptxt_creations();
int get_ptxt_destructions();

int get_ctxt_creations();
int get_ctxt_destructions();

}  // namespace aluminum_shark

#endif /* ALUMINUM_SHARK_COMMON_OBJECT_COUNT_H */
