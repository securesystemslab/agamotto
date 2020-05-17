/*
 * libafl.h
 */

#ifndef _LIBAFL_H_
#define _LIBAFL_H_

#include <stdint.h>
#include <stdlib.h>

#define USE_AFL_FUZZ_ONE
#define SKIP_PERISCOPE_MUTATORS
//#define SKIP_BITFLIP
//#define SKIP_ARITH

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
// typedef uint64_t u64;

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

u8 libafl_setup(u8 *opt_i, u8 *opt_o, u8 *opt_dict, u8 *opt_f, s32 ctrl_fd,
                s32 status_fd, u8 opt_n, u8 opt_d, u8 *opt_M, u8 *opt_S, u32 seed);
void libafl_perform_dry_run(void);
u8 libafl_fuzz_one(void);
void libafl_destroy(void);

u8 libafl_get_queue_cur_info(void);

#endif // _LIBAFL_H_
