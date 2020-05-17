/*
 * libafl.c
 *
 * Authors:
 *  dokyungs@uci.edu
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>

#include <afl-2.52b/alloc-inl.h>
#include <afl-2.52b/config.h>
#include <afl-2.52b/debug.h>
#include <afl-2.52b/hash.h>

#include "libafl.h"

extern s32 in_seed;

extern volatile u8 stop_soon; /* Ctrl-C pressed?                  */

extern u8 skip_deterministic, /* Skip deterministic stages?       */
    force_deterministic,      /* Force deterministic stages?      */
    use_splicing,             /* Recombine input files?           */
    dumb_mode,                /* Run in non-instrumented mode?    */
    timeout_given,            /* Specific timeout given?          */
    not_on_tty,               /* stdout is not a tty              */
    no_forkserver,            /* Disable forkserver?              */
    crash_mode,               /* Crash mode! Yeah!                */
    in_place_resume,          /* Attempt in-place resume?         */
    no_arith;                 /* Skip most arithmetic ops         */

extern s32 dev_urandom_fd, /* Persistent fd for /dev/urandom   */
    fsrv_ctl_fd,           /* Fork server control pipe (write) */
    fsrv_st_fd;            /* Fork server status pipe (read)   */

extern s32 forksrv_pid; /* PID of the fork server           */

extern u8 *trace_bits; /* SHM with instrumentation bitmap  */

extern u8 *in_dir, /* Input directory with test cases  */
    *out_file,     /* File to fuzz, if any             */
    *out_dir,      /* Working & output directory       */
    *sync_id;      /* Fuzzer ID                        */

extern u32 exec_tmout; /* Configurable exec timeout (ms)   */

extern u32 cur_skipped_paths, /* Abandoned inputs in cur cycle    */
    current_entry;            /* Current queue entry ID           */

extern FILE *plot_file; /* Gnuplot output file              */

struct queue_entry {
    u8 *fname; /* File name for the test case      */
    u32 len;   /* Input length                     */

    u8 cal_failed,    /* Calibration failed?              */
        trim_done,    /* Trimmed?                         */
        was_fuzzed,   /* Had any fuzzing done yet?        */
        passed_det,   /* Deterministic stages passed?     */
        has_new_cov,  /* Triggers new coverage?           */
        var_behavior, /* Variable behavior?               */
        favored,      /* Currently favored?               */
        fs_redundant; /* Marked as redundant in the fs?   */

    u32 bitmap_size, /* Number of bits set in bitmap     */
        exec_cksum;  /* Checksum of the execution trace  */

    u64 exec_us,  /* Execution time (us)              */
        handicap, /* Number of queue cycles behind    */
        depth;    /* Path depth                       */

    u8 *trace_mini; /* Trace bytes, if kept             */
    u32 tc_ref;     /* Trace bytes ref count            */

    struct queue_entry *next, /* Next element, if any             */
        *next_100;            /* 100 elements ahead               */
};

extern struct queue_entry *queue, /* Fuzzing queue (linked list)      */
    *queue_cur;                   /* Current offset within the queue  */

extern u64 unique_crashes, /* Crashes with unique signatures   */
    start_time,            /* Unix start time (ms)             */
    queue_cycle,           /* Queue round counter              */
    cycles_wo_finds,       /* Cycles without any new paths     */
    blocks_eff_total,      /* Blocks subject to effector maps  */
    blocks_eff_select;     /* Blocks selected as fuzzable      */

extern u32 queued_paths, /* Total number of queued testcases */
    pending_not_fuzzed,  /* Queued but not done yet          */
    pending_favored,     /* Pending favored paths            */
    cur_depth,           /* Current path depth               */
    havoc_div;           /* Cycle count divisor for havoc    */

extern u32 subseq_tmouts; /* Number of timeouts in a row      */
extern u8 *stage_name,    /* Name of the current fuzz stage   */
    *stage_short,         /* Short stage name                 */
    *syncing_party;       /* Currently syncing with...        */

extern s32 stage_cur, stage_max; /* Stage progression                */

extern s32 splicing_with; /* Splicing with which test case?   */

extern u32 master_id, master_max; /* Master instance job splitting    */

extern s32 stage_cur_byte, /* Byte offset of current stage op  */
    stage_cur_val;         /* Value used for stage op          */

extern u8 stage_val_type; /* Value type (STAGE_VAL_*)         */

extern u64 stage_finds[32], /* Patterns found per fuzz stage    */
    stage_cycles[32];       /* Execs per fuzz stage             */

struct extra_data {
    u8 *data;    /* Dictionary token data            */
    u32 len;     /* Dictionary token length          */
    u32 hit_cnt; /* Use count in the corpus          */
};

extern struct extra_data *extras; /* Extra tokens to fuzz with        */
extern u32 extras_cnt;            /* Total number of tokens read      */

extern struct extra_data *a_extras; /* Automatically selected extras    */
extern u32 a_extras_cnt;            /* Total number of tokens available */

static s8 interesting_8[] = {INTERESTING_8};
static s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
static s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

enum {
    /* 00 */ STAGE_FLIP1,
    /* 01 */ STAGE_FLIP2,
    /* 02 */ STAGE_FLIP4,
    /* 03 */ STAGE_FLIP8,
    /* 04 */ STAGE_FLIP16,
    /* 05 */ STAGE_FLIP32,
    /* 06 */ STAGE_ARITH8,
    /* 07 */ STAGE_ARITH16,
    /* 08 */ STAGE_ARITH32,
    /* 09 */ STAGE_INTEREST8,
    /* 10 */ STAGE_INTEREST16,
    /* 11 */ STAGE_INTEREST32,
    /* 12 */ STAGE_EXTRAS_UO,
    /* 13 */ STAGE_EXTRAS_UI,
    /* 14 */ STAGE_EXTRAS_AO,
    /* 15 */ STAGE_HAVOC,
    /* 16 */ STAGE_SPLICE
};

/* PeriScope stages */

enum {
    /* 17 */ STAGE_APPEND32 = STAGE_SPLICE + 1,
    /* 18 */ STAGE_APPEND64
};

/* Stage value types */

enum {
    /* 00 */ STAGE_VAL_NONE,
    /* 01 */ STAGE_VAL_LE,
    /* 02 */ STAGE_VAL_BE
};

/* Execution status fault codes */

enum {
    /* 00 */ FAULT_NONE,
    /* 01 */ FAULT_TMOUT,
    /* 02 */ FAULT_CRASH,
    /* 03 */ FAULT_ERROR,
    /* 04 */ FAULT_NOINST,
    /* 05 */ FAULT_NOBITS
};

static u64 prev_queued = 0;

void perform_dry_run(char **argv);
void cull_queue(void);
void show_stats(void);
u8 trim_case(char **argv, struct queue_entry *q, u8 *in_buf);
u8 calibrate_case(char **argv, struct queue_entry *q, u8 *use_mem, u32 handicap,
                  u8 from_queue);
u8 fuzz_one(char **argv);
void sync_fuzzers(char **argv);

u32 calculate_score(struct queue_entry *q);
u8 could_be_bitflip(u32 xor_val);
u8 could_be_arith(u32 old_val, u32 new_val, u8 blen);
u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le);
void locate_diffs(u8 *ptr1, u8 *ptr2, u32 len, s32 *first, s32 *last);
u8 common_fuzz_stuff(char **argv, u8 *out_buf, u32 len);
void maybe_add_auto(u8 *mem, u32 len);
u32 choose_block_len(u32 limit);
void mark_as_det_done(struct queue_entry *q);

u64 get_cur_time(void);
void setup_shm(void);
void setup_dirs_fds(void);
void init_count_class16(void);
void destroy_queue(void);
void destroy_extras(void);
void load_auto(void);
void save_auto(void);
void pivot_inputs(void);
void load_extras(u8 *dir);
void read_testcases(void);
void fix_up_sync(void);
u32 find_start_position(void);
void show_init_stats(void);
void write_stats_file(double bitmap_cvg, double stability, double eps);
void write_bitmap(void);

static u32 seek_to;
static u8 exit_1;

u8 libafl_setup(u8 *opt_i, u8 *opt_o, u8 *opt_dict, u8 *opt_f, s32 ctrl_fd,
                s32 status_fd, u8 opt_n, u8 opt_d, u8 *opt_M, u8 *opt_S,
                u32 seed) {

    exit_1 = !!getenv("AFL_BENCH_JUST_ONE");

    if (opt_f == NULL)
        return 0;

    if (seed != -1) {
        in_seed = seed;
    }

    /*
     * variables initialized via command-line arguments and/or env variables
     */
    in_dir = opt_i; // -i
    if (!strcmp(in_dir, "-"))
        in_place_resume = 1;
    out_file = opt_f; // -f
    out_dir = opt_o;  // -o
    dumb_mode = 0;
    if (opt_n) {
        dumb_mode = 2; // -n + AFL_DUMB_FORKSRV
    }
    if (opt_d) {
        skip_deterministic = 1; // -d
        use_splicing = 1;       // -d
    }
    not_on_tty = 1;     // AFL_NO_UI
    exec_tmout = 30000; // -t (hard-limit on timeout)
    timeout_given = 1;  // -t
    if (opt_M) {
        sync_id = strdup(opt_M); // -M
        force_deterministic = 1;
    } else if (opt_S) {
        sync_id = strdup(opt_S); // -S
    }

    if (sync_id)
        fix_up_sync();

    // Make afl think that it is talking to a fork server
    forksrv_pid = -1;
    fsrv_ctl_fd = ctrl_fd;
    fsrv_st_fd = status_fd;

    setup_shm(); // won't have effect until we turn off dumb_mode
    init_count_class16();

    setup_dirs_fds();
    read_testcases();
    load_auto();

    pivot_inputs();

    if (strlen(opt_dict) > 0)
        load_extras(opt_dict);

    start_time = get_cur_time();

    return 1;
}

void libafl_perform_dry_run(void) {
    char *argv[] = {""};
    perform_dry_run(argv);

    cull_queue();

    show_init_stats();

    seek_to = find_start_position();

    write_stats_file(0, 0, 0);
    save_auto();
}

u8 libafl_get_queue_cur_info(void) {
    if (queue_cur) {
        return queue_cur->favored;
    }
    return 0;
}

static u32 rand_cnt; /* Random number counter            */

/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

static inline u32 UR(u32 limit) {

    // if (unlikely(!rand_cnt--)) {

    //    u32 seed[2];

    //    ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

    //    srandom(seed[0]);
    //    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);
    //}

    return random() % limit;
}

#ifndef USE_AFL_FUZZ_ONE
static u8 _fuzz_one(char **argv) {
    s32 len, fd, temp_len, i, j;
    u8 *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
    u64 havoc_queued, orig_hit_cnt, new_hit_cnt;
    u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

    u8 ret_val = 1, doing_det = 0;

    u8 a_collect[MAX_AUTO_EXTRA];
    u32 a_len = 0;

#ifdef IGNORE_FINDS

    /* In IGNORE_FINDS mode, skip any entries that weren't in the
       initial data set. */

    if (queue_cur->depth > 1)
        return 1;

#else

    if (pending_favored) {

        /* If we have any favored, non-fuzzed new arrivals in the queue,
           possibly skip to them at the expense of already-fuzzed or non-favored
           cases. */

        if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
            UR(100) < SKIP_TO_NEW_PROB)
            return 1;

    } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {

        /* Otherwise, still possibly skip non-favored cases, albeit less often.
           The odds of skipping stuff are higher for already-fuzzed inputs and
           lower for never-fuzzed entries. */

        if (queue_cycle > 1 && !queue_cur->was_fuzzed) {

            if (UR(100) < SKIP_NFAV_NEW_PROB)
                return 1;

        } else {

            if (UR(100) < SKIP_NFAV_OLD_PROB)
                return 1;
        }
    }

#endif /* ^IGNORE_FINDS */

    if (not_on_tty) {
        ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
             current_entry, queued_paths, unique_crashes);
        fflush(stdout);
    }

    /* Map the test case into memory. */

    fd = open(queue_cur->fname, O_RDONLY);

    if (fd < 0)
        PFATAL("Unable to open '%s'", queue_cur->fname);

    len = queue_cur->len;

    orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (orig_in == MAP_FAILED)
        PFATAL("Unable to mmap '%s'", queue_cur->fname);

    close(fd);

    /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
       single byte anyway, so it wouldn't give us any performance or memory
       usage benefits. */

    out_buf = ck_alloc_nozero(len);

    subseq_tmouts = 0;

    cur_depth = queue_cur->depth;

    /*******************************************
     * CALIBRATION (only if failed earlier on) *
     *******************************************/

    if (queue_cur->cal_failed) {

        u8 res = FAULT_TMOUT;

        if (queue_cur->cal_failed < CAL_CHANCES) {

            res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);

            if (res == FAULT_ERROR)
                FATAL("Unable to execute target application");
        }

        if (stop_soon || res != crash_mode) {
            cur_skipped_paths++;
            goto abandon_entry;
        }
    }

    /************
     * TRIMMING *
     ************/

    if (!dumb_mode && !queue_cur->trim_done) {

        u8 res = trim_case(argv, queue_cur, in_buf);

        if (res == FAULT_ERROR)
            FATAL("Unable to execute target application");

        if (stop_soon) {
            cur_skipped_paths++;
            goto abandon_entry;
        }

        /* Don't retry trimming, even if it failed. */

        queue_cur->trim_done = 1;

        if (len != queue_cur->len)
            len = queue_cur->len;
    }

    memcpy(out_buf, in_buf, len);

    /*********************
     * PERFORMANCE SCORE *
     *********************/

    orig_perf = perf_score = calculate_score(queue_cur);

    /* Skip right away if -d is given, if we have done deterministic fuzzing on
       this entry ourselves (was_fuzzed), or if it has gone through
       deterministic testing in earlier, resumed runs (passed_det). */

    if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
        goto havoc_stage;

    /* Skip deterministic fuzzing if exec path checksum puts this out of scope
       for this master instance. */

    if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
        goto havoc_stage;

    doing_det = 1;

    new_hit_cnt = queued_paths + unique_crashes;

#ifdef SKIP_PERISCOPE_MUTATORS
    goto skip_periscope_mutators;
#endif

    /*********************************************
     * AGAMOTTO MUTATORS                         *
     *********************************************/

    /* 4 byte append */
    stage_name = "append 32";
    stage_short = "append32";
    stage_max = (len << 3) - 1;

    stage_val_type = STAGE_VAL_LE;

    orig_hit_cnt = new_hit_cnt;

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_APPEND32] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_APPEND32] += stage_max;

    /* 8 byte append */
    stage_name = "append 64";
    stage_short = "append64";
    stage_max = (len << 3) - 1;

    stage_val_type = STAGE_VAL_LE;

    orig_hit_cnt = queued_paths + unique_crashes;

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_APPEND64] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_APPEND64] += stage_max;

skip_periscope_mutators:

#ifdef SKIP_BITFLIP
    goto skip_bitflip;
#endif

    /*********************************************
     * SIMPLE BITFLIP (+dictionary construction) *
     *********************************************/

#define FLIP_BIT(_ar, _b)                                                      \
    do {                                                                       \
        u8 *_arf = (u8 *)(_ar);                                                \
        u32 _bf = (_b);                                                        \
        _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7));                                \
    } while (0)

    /* Single walking bit. */

    stage_short = "flip1";
    stage_max = len << 3;
    stage_name = "bitflip 1/1";

    stage_val_type = STAGE_VAL_NONE;

    orig_hit_cnt = new_hit_cnt;

    prev_cksum = queue_cur->exec_cksum;

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

        stage_cur_byte = stage_cur >> 3;

        FLIP_BIT(out_buf, stage_cur);

        if (common_fuzz_stuff(argv, out_buf, len))
            goto abandon_entry;

        FLIP_BIT(out_buf, stage_cur);

        /* While flipping the least significant bit in every byte, pull of an
           extra trick to detect possible syntax tokens. In essence, the idea is
           that if you have a binary blob like this:

           xxxxxxxxIHDRxxxxxxxx

           ...and changing the leading and trailing bytes causes variable or no
           changes in program flow, but touching any character in the "IHDR"
           string always produces the same, distinctive path, it's highly likely
           that "IHDR" is an atomically-checked magic value of special
           significance to the fuzzed format.

           We do this here, rather than as a separate stage, because it's a nice
           way to keep the operation approximately "free" (i.e., no extra
           execs).

           Empirically, performing the check when flipping the least significant
           bit is advantageous, compared to doing it at the time of more
           disruptive changes, where the program flow may be affected in more
           violent ways.

           The caveat is that we won't generate dictionaries in the -d mode or
           -S mode - but that's probably a fair trade-off.

           This won't work particularly well with paths that exhibit variable
           behavior, but fails gracefully, so we'll carry out the checks anyway.

          */

        if (!dumb_mode && (stage_cur & 7) == 7) {

            u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

            if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

                /* If at end of file and we are still collecting a string, grab
                   the final character and force output. */

                if (a_len < MAX_AUTO_EXTRA)
                    a_collect[a_len] = out_buf[stage_cur >> 3];
                a_len++;

                if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
                    maybe_add_auto(a_collect, a_len);

            } else if (cksum != prev_cksum) {

                /* Otherwise, if the checksum has changed, see if we have
                   something worthwhile queued up, and collect that if the
                   answer is yes. */

                if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
                    maybe_add_auto(a_collect, a_len);

                a_len = 0;
                prev_cksum = cksum;
            }

            /* Continue collecting string, but only if the bit flip actually
               made any difference - we don't want no-op tokens. */

            if (cksum != queue_cur->exec_cksum) {

                if (a_len < MAX_AUTO_EXTRA)
                    a_collect[a_len] = out_buf[stage_cur >> 3];
                a_len++;
            }
        }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP1] += stage_max;

    /* Two walking bits. */

    stage_name = "bitflip 2/1";
    stage_short = "flip2";
    stage_max = (len << 3) - 1;

    orig_hit_cnt = new_hit_cnt;

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

        stage_cur_byte = stage_cur >> 3;

        FLIP_BIT(out_buf, stage_cur);
        FLIP_BIT(out_buf, stage_cur + 1);

        if (common_fuzz_stuff(argv, out_buf, len))
            goto abandon_entry;

        FLIP_BIT(out_buf, stage_cur);
        FLIP_BIT(out_buf, stage_cur + 1);
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP2] += stage_max;

    /* Four walking bits. */

    stage_name = "bitflip 4/1";
    stage_short = "flip4";
    stage_max = (len << 3) - 3;

    orig_hit_cnt = new_hit_cnt;

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

        stage_cur_byte = stage_cur >> 3;

        FLIP_BIT(out_buf, stage_cur);
        FLIP_BIT(out_buf, stage_cur + 1);
        FLIP_BIT(out_buf, stage_cur + 2);
        FLIP_BIT(out_buf, stage_cur + 3);

        if (common_fuzz_stuff(argv, out_buf, len))
            goto abandon_entry;

        FLIP_BIT(out_buf, stage_cur);
        FLIP_BIT(out_buf, stage_cur + 1);
        FLIP_BIT(out_buf, stage_cur + 2);
        FLIP_BIT(out_buf, stage_cur + 3);
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP4] += stage_max;

    /* Effector map setup. These macros calculate:

       EFF_APOS      - position of a particular file offset in the map.
       EFF_ALEN      - length of a map with a particular number of bytes.
       EFF_SPAN_ALEN - map span for a sequence of bytes.

     */

#define EFF_APOS(_p) ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x) ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l) (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l)-1) - EFF_APOS(_p) + 1)

    /* Initialize effector map for the next step (see comments below). Always
       flag first and last byte as doing something. */

    eff_map = ck_alloc(EFF_ALEN(len));
    eff_map[0] = 1;

    if (EFF_APOS(len - 1) != 0) {
        eff_map[EFF_APOS(len - 1)] = 1;
        eff_cnt++;
    }

    /* Walking byte. */

    stage_name = "bitflip 8/8";
    stage_short = "flip8";
    stage_max = len;

    orig_hit_cnt = new_hit_cnt;

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

        stage_cur_byte = stage_cur;

        out_buf[stage_cur] ^= 0xFF;

        if (common_fuzz_stuff(argv, out_buf, len))
            goto abandon_entry;

        /* We also use this stage to pull off a simple trick: we identify
           bytes that seem to have no effect on the current execution path
           even when fully flipped - and we skip them during more expensive
           deterministic stages, such as arithmetics or known ints. */

        if (!eff_map[EFF_APOS(stage_cur)]) {

            u32 cksum;

            /* If in dumb mode or if the file is very short, just flag
               everything without wasting time on checksums. */

            if (!dumb_mode && len >= EFF_MIN_LEN)
                cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
            else
                cksum = ~queue_cur->exec_cksum;

            if (cksum != queue_cur->exec_cksum) {
                eff_map[EFF_APOS(stage_cur)] = 1;
                eff_cnt++;
            }
        }

        out_buf[stage_cur] ^= 0xFF;
    }

    /* If the effector map is more than EFF_MAX_PERC dense, just flag the
       whole thing as worth fuzzing, since we wouldn't be saving much time
       anyway. */

    if (eff_cnt != EFF_ALEN(len) &&
        eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

        memset(eff_map, 1, EFF_ALEN(len));

        blocks_eff_select += EFF_ALEN(len);

    } else {

        blocks_eff_select += eff_cnt;
    }

    blocks_eff_total += EFF_ALEN(len);

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP8] += stage_max;

    /* Two walking bytes. */

    if (len < 2)
        goto skip_bitflip;

    stage_name = "bitflip 16/8";
    stage_short = "flip16";
    stage_cur = 0;
    stage_max = len - 1;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 1; i++) {

        /* Let's consult the effector map... */

        if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
            stage_max--;
            continue;
        }

        stage_cur_byte = i;

        *(u16 *)(out_buf + i) ^= 0xFFFF;

        if (common_fuzz_stuff(argv, out_buf, len))
            goto abandon_entry;
        stage_cur++;

        *(u16 *)(out_buf + i) ^= 0xFFFF;
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP16] += stage_max;

    if (len < 4)
        goto skip_bitflip;

    /* Four walking bytes. */

    stage_name = "bitflip 32/8";
    stage_short = "flip32";
    stage_cur = 0;
    stage_max = len - 3;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 3; i++) {

        /* Let's consult the effector map... */
        if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
            !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
            stage_max--;
            continue;
        }

        stage_cur_byte = i;

        *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

        if (common_fuzz_stuff(argv, out_buf, len))
            goto abandon_entry;
        stage_cur++;

        *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP32] += stage_max;

skip_bitflip:

    if (no_arith)
        goto skip_arith;

#ifdef SKIP_ARITH
    goto skip_arith;
#endif

    /**********************
     * ARITHMETIC INC/DEC *
     **********************/

    /* 8-bit arithmetics. */

    stage_name = "arith 8/8";
    stage_short = "arith8";
    stage_cur = 0;
    stage_max = 2 * len * ARITH_MAX;

    stage_val_type = STAGE_VAL_LE;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len; i++) {

        u8 orig = out_buf[i];

        /* Let's consult the effector map... */

        if (!eff_map[EFF_APOS(i)]) {
            stage_max -= 2 * ARITH_MAX;
            continue;
        }

        stage_cur_byte = i;

        for (j = 1; j <= ARITH_MAX; j++) {

            u8 r = orig ^ (orig + j);

            /* Do arithmetic operations only if the result couldn't be a product
               of a bitflip. */

            if (!could_be_bitflip(r)) {

                stage_cur_val = j;
                out_buf[i] = orig + j;

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;

            r = orig ^ (orig - j);

            if (!could_be_bitflip(r)) {

                stage_cur_val = -j;
                out_buf[i] = orig - j;

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;

            out_buf[i] = orig;
        }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_ARITH8] += stage_max;

    /* 16-bit arithmetics, both endians. */

    if (len < 2)
        goto skip_arith;

    stage_name = "arith 16/8";
    stage_short = "arith16";
    stage_cur = 0;
    stage_max = 4 * (len - 1) * ARITH_MAX;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 1; i++) {

        u16 orig = *(u16 *)(out_buf + i);

        /* Let's consult the effector map... */

        if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
            stage_max -= 4 * ARITH_MAX;
            continue;
        }

        stage_cur_byte = i;

        for (j = 1; j <= ARITH_MAX; j++) {

            u16 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
                r3 = orig ^ SWAP16(SWAP16(orig) + j),
                r4 = orig ^ SWAP16(SWAP16(orig) - j);

            /* Try little endian addition and subtraction first. Do it only
               if the operation would affect more than one byte (hence the
               & 0xff overflow checks) and if it couldn't be a product of
               a bitflip. */

            stage_val_type = STAGE_VAL_LE;

            if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

                stage_cur_val = j;
                *(u16 *)(out_buf + i) = orig + j;

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;

            if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

                stage_cur_val = -j;
                *(u16 *)(out_buf + i) = orig - j;

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;

            /* Big endian comes next. Same deal. */

            stage_val_type = STAGE_VAL_BE;

            if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

                stage_cur_val = j;
                *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) + j);

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;

            if ((orig >> 8) < j && !could_be_bitflip(r4)) {

                stage_cur_val = -j;
                *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) - j);

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;

            *(u16 *)(out_buf + i) = orig;
        }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_ARITH16] += stage_max;

    /* 32-bit arithmetics, both endians. */

    if (len < 4)
        goto skip_arith;

    stage_name = "arith 32/8";
    stage_short = "arith32";
    stage_cur = 0;
    stage_max = 4 * (len - 3) * ARITH_MAX;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 3; i++) {

        u32 orig = *(u32 *)(out_buf + i);

        /* Let's consult the effector map... */

        if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
            !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
            stage_max -= 4 * ARITH_MAX;
            continue;
        }

        stage_cur_byte = i;

        for (j = 1; j <= ARITH_MAX; j++) {

            u32 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
                r3 = orig ^ SWAP32(SWAP32(orig) + j),
                r4 = orig ^ SWAP32(SWAP32(orig) - j);

            /* Little endian first. Same deal as with 16-bit: we only want to
               try if the operation would have effect on more than two bytes. */

            stage_val_type = STAGE_VAL_LE;

            if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

                stage_cur_val = j;
                *(u32 *)(out_buf + i) = orig + j;

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;

            if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

                stage_cur_val = -j;
                *(u32 *)(out_buf + i) = orig - j;

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;

            /* Big endian next. */

            stage_val_type = STAGE_VAL_BE;

            if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

                stage_cur_val = j;
                *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) + j);

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;

            if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

                stage_cur_val = -j;
                *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) - j);

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;

            *(u32 *)(out_buf + i) = orig;
        }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_ARITH32] += stage_max;

skip_arith:

    /**********************
     * INTERESTING VALUES *
     **********************/

    stage_name = "interest 8/8";
    stage_short = "int8";
    stage_cur = 0;
    stage_max = len * sizeof(interesting_8);

    stage_val_type = STAGE_VAL_LE;

    orig_hit_cnt = new_hit_cnt;

    /* Setting 8-bit integers. */

    for (i = 0; i < len; i++) {

        u8 orig = out_buf[i];

        /* Let's consult the effector map... */

        if (!eff_map[EFF_APOS(i)]) {
            stage_max -= sizeof(interesting_8);
            continue;
        }

        stage_cur_byte = i;

        for (j = 0; j < sizeof(interesting_8); j++) {

            /* Skip if the value could be a product of bitflips or arithmetics.
             */

            if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
                could_be_arith(orig, (u8)interesting_8[j], 1)) {
                stage_max--;
                continue;
            }

            stage_cur_val = interesting_8[j];
            out_buf[i] = interesting_8[j];

            if (common_fuzz_stuff(argv, out_buf, len))
                goto abandon_entry;

            out_buf[i] = orig;
            stage_cur++;
        }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_INTEREST8] += stage_max;

    /* Setting 16-bit integers, both endians. */

    if (no_arith || len < 2)
        goto skip_interest;

    stage_name = "interest 16/8";
    stage_short = "int16";
    stage_cur = 0;
    stage_max = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 1; i++) {

        u16 orig = *(u16 *)(out_buf + i);

        /* Let's consult the effector map... */

        if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
            stage_max -= sizeof(interesting_16);
            continue;
        }

        stage_cur_byte = i;

        for (j = 0; j < sizeof(interesting_16) / 2; j++) {

            stage_cur_val = interesting_16[j];

            /* Skip if this could be a product of a bitflip, arithmetics,
               or single-byte interesting value insertion. */

            if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
                !could_be_arith(orig, (u16)interesting_16[j], 2) &&
                !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

                stage_val_type = STAGE_VAL_LE;

                *(u16 *)(out_buf + i) = interesting_16[j];

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;

            if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
                !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
                !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
                !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

                stage_val_type = STAGE_VAL_BE;

                *(u16 *)(out_buf + i) = SWAP16(interesting_16[j]);
                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;
        }

        *(u16 *)(out_buf + i) = orig;
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_INTEREST16] += stage_max;

    if (len < 4)
        goto skip_interest;

    /* Setting 32-bit integers, both endians. */

    stage_name = "interest 32/8";
    stage_short = "int32";
    stage_cur = 0;
    stage_max = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 3; i++) {

        u32 orig = *(u32 *)(out_buf + i);

        /* Let's consult the effector map... */

        if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
            !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
            stage_max -= sizeof(interesting_32) >> 1;
            continue;
        }

        stage_cur_byte = i;

        for (j = 0; j < sizeof(interesting_32) / 4; j++) {

            stage_cur_val = interesting_32[j];

            /* Skip if this could be a product of a bitflip, arithmetics,
               or word interesting value insertion. */

            if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
                !could_be_arith(orig, interesting_32[j], 4) &&
                !could_be_interest(orig, interesting_32[j], 4, 0)) {

                stage_val_type = STAGE_VAL_LE;

                *(u32 *)(out_buf + i) = interesting_32[j];

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;

            if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
                !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
                !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
                !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

                stage_val_type = STAGE_VAL_BE;

                *(u32 *)(out_buf + i) = SWAP32(interesting_32[j]);
                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;

            } else
                stage_max--;
        }

        *(u32 *)(out_buf + i) = orig;
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_INTEREST32] += stage_max;

skip_interest:

    /********************
     * DICTIONARY STUFF *
     ********************/

    if (!extras_cnt)
        goto skip_user_extras;

    /* Overwrite with user-supplied extras. */

    stage_name = "user extras (over)";
    stage_short = "ext_UO";
    stage_cur = 0;
    stage_max = extras_cnt * len;

    stage_val_type = STAGE_VAL_NONE;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len; i++) {

        u32 last_len = 0;

        stage_cur_byte = i;

        /* Extras are sorted by size, from smallest to largest. This means
           that we don't have to worry about restoring the buffer in
           between writes at a particular offset determined by the outer
           loop. */

        for (j = 0; j < extras_cnt; j++) {

            /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS.
               Also skip them if there's no room to insert the payload, if the
               token is redundant, or if its entire span has no bytes set in the
               effector map. */

            if ((extras_cnt > MAX_DET_EXTRAS &&
                 UR(extras_cnt) >= MAX_DET_EXTRAS) ||
                extras[j].len > len - i ||
                !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
                !memchr(eff_map + EFF_APOS(i), 1,
                        EFF_SPAN_ALEN(i, extras[j].len))) {

                stage_max--;
                continue;
            }

            last_len = extras[j].len;
            memcpy(out_buf + i, extras[j].data, last_len);

            if (common_fuzz_stuff(argv, out_buf, len))
                goto abandon_entry;

            stage_cur++;
        }

        /* Restore all the clobbered memory. */
        memcpy(out_buf + i, in_buf + i, last_len);
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_UO] += stage_max;

    /* Insertion of user-supplied extras. */

    stage_name = "user extras (insert)";
    stage_short = "ext_UI";
    stage_cur = 0;
    stage_max = extras_cnt * len;

    orig_hit_cnt = new_hit_cnt;

    ex_tmp = ck_alloc(len + MAX_DICT_FILE);

    for (i = 0; i <= len; i++) {

        stage_cur_byte = i;

        for (j = 0; j < extras_cnt; j++) {

            if (len + extras[j].len > MAX_FILE) {
                stage_max--;
                continue;
            }

            /* Insert token */
            memcpy(ex_tmp + i, extras[j].data, extras[j].len);

            /* Copy tail */
            memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

            if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len)) {
                ck_free(ex_tmp);
                goto abandon_entry;
            }

            stage_cur++;
        }

        /* Copy head */
        ex_tmp[i] = out_buf[i];
    }

    ck_free(ex_tmp);

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_UI] += stage_max;

skip_user_extras:

    if (!a_extras_cnt)
        goto skip_extras;

    stage_name = "auto extras (over)";
    stage_short = "ext_AO";
    stage_cur = 0;
    stage_max = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;

    stage_val_type = STAGE_VAL_NONE;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len; i++) {

        u32 last_len = 0;

        stage_cur_byte = i;

        for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {

            /* See the comment in the earlier code; extras are sorted by size.
             */

            if (a_extras[j].len > len - i ||
                !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
                !memchr(eff_map + EFF_APOS(i), 1,
                        EFF_SPAN_ALEN(i, a_extras[j].len))) {

                stage_max--;
                continue;
            }

            last_len = a_extras[j].len;
            memcpy(out_buf + i, a_extras[j].data, last_len);

            if (common_fuzz_stuff(argv, out_buf, len))
                goto abandon_entry;

            stage_cur++;
        }

        /* Restore all the clobbered memory. */
        memcpy(out_buf + i, in_buf + i, last_len);
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_AO] += stage_max;

skip_extras:

    /* If we made this to here without jumping to havoc_stage or abandon_entry,
       we're properly done with deterministic steps and can mark it as such
       in the .state/ directory. */

    if (!queue_cur->passed_det)
        mark_as_det_done(queue_cur);

    /****************
     * RANDOM HAVOC *
     ****************/

havoc_stage:

    stage_cur_byte = -1;

    /* The havoc stage mutation code is also invoked when splicing files; if the
       splice_cycle variable is set, generate different descriptions and such.
     */

    if (!splice_cycle) {

        stage_name = "havoc";
        stage_short = "havoc";
        stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                    perf_score / havoc_div / 100;

    } else {

        static u8 tmp[32];

        perf_score = orig_perf;

        sprintf(tmp, "splice %u", splice_cycle);
        stage_name = tmp;
        stage_short = "splice";
        stage_max = SPLICE_HAVOC * perf_score / havoc_div / 100;
    }

    if (stage_max < HAVOC_MIN)
        stage_max = HAVOC_MIN;

    temp_len = len;

    orig_hit_cnt = queued_paths + unique_crashes;

    havoc_queued = queued_paths;

    /* We essentially just do several thousand runs (depending on perf_score)
       where we take the input file and make random stacked tweaks. */

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

        u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

        stage_cur_val = use_stacking;

        for (i = 0; i < use_stacking; i++) {

            switch (UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0))) {

            case 0:

                /* Flip a single bit somewhere. Spooky! */

                FLIP_BIT(out_buf, UR(temp_len << 3));
                break;

            case 1:

                /* Set byte to interesting value. */

                out_buf[UR(temp_len)] =
                    interesting_8[UR(sizeof(interesting_8))];
                break;

            case 2:

                /* Set word to interesting value, randomly choosing endian. */

                if (temp_len < 2)
                    break;

                if (UR(2)) {

                    *(u16 *)(out_buf + UR(temp_len - 1)) =
                        interesting_16[UR(sizeof(interesting_16) >> 1)];

                } else {

                    *(u16 *)(out_buf + UR(temp_len - 1)) =
                        SWAP16(interesting_16[UR(sizeof(interesting_16) >> 1)]);
                }

                break;

            case 3:

                /* Set dword to interesting value, randomly choosing endian. */

                if (temp_len < 4)
                    break;

                if (UR(2)) {

                    *(u32 *)(out_buf + UR(temp_len - 3)) =
                        interesting_32[UR(sizeof(interesting_32) >> 2)];

                } else {

                    *(u32 *)(out_buf + UR(temp_len - 3)) =
                        SWAP32(interesting_32[UR(sizeof(interesting_32) >> 2)]);
                }

                break;

            case 4:

                /* Randomly subtract from byte. */

                out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
                break;

            case 5:

                /* Randomly add to byte. */

                out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
                break;

            case 6:

                /* Randomly subtract from word, random endian. */

                if (temp_len < 2)
                    break;

                if (UR(2)) {

                    u32 pos = UR(temp_len - 1);

                    *(u16 *)(out_buf + pos) -= 1 + UR(ARITH_MAX);

                } else {

                    u32 pos = UR(temp_len - 1);
                    u16 num = 1 + UR(ARITH_MAX);

                    *(u16 *)(out_buf + pos) =
                        SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);
                }

                break;

            case 7:

                /* Randomly add to word, random endian. */

                if (temp_len < 2)
                    break;

                if (UR(2)) {

                    u32 pos = UR(temp_len - 1);

                    *(u16 *)(out_buf + pos) += 1 + UR(ARITH_MAX);

                } else {

                    u32 pos = UR(temp_len - 1);
                    u16 num = 1 + UR(ARITH_MAX);

                    *(u16 *)(out_buf + pos) =
                        SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);
                }

                break;

            case 8:

                /* Randomly subtract from dword, random endian. */

                if (temp_len < 4)
                    break;

                if (UR(2)) {

                    u32 pos = UR(temp_len - 3);

                    *(u32 *)(out_buf + pos) -= 1 + UR(ARITH_MAX);

                } else {

                    u32 pos = UR(temp_len - 3);
                    u32 num = 1 + UR(ARITH_MAX);

                    *(u32 *)(out_buf + pos) =
                        SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);
                }

                break;

            case 9:

                /* Randomly add to dword, random endian. */

                if (temp_len < 4)
                    break;

                if (UR(2)) {

                    u32 pos = UR(temp_len - 3);

                    *(u32 *)(out_buf + pos) += 1 + UR(ARITH_MAX);

                } else {

                    u32 pos = UR(temp_len - 3);
                    u32 num = 1 + UR(ARITH_MAX);

                    *(u32 *)(out_buf + pos) =
                        SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);
                }

                break;

            case 10:

                /* Just set a random byte to a random value. Because,
                   why not. We use XOR with 1-255 to eliminate the
                   possibility of a no-op. */

                out_buf[UR(temp_len)] ^= 1 + UR(255);
                break;

            case 11 ... 12: {

                /* Delete bytes. We're making this a bit more likely
                   than insertion (the next option) in hopes of keeping
                   files reasonably small. */

                u32 del_from, del_len;

                if (temp_len < 2)
                    break;

                /* Don't delete too much. */

                del_len = choose_block_len(temp_len - 1);

                del_from = UR(temp_len - del_len + 1);

                memmove(out_buf + del_from, out_buf + del_from + del_len,
                        temp_len - del_from - del_len);

                temp_len -= del_len;

                break;
            }

            case 13:

                if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

                    /* Clone bytes (75%) or insert a block of constant bytes
                     * (25%). */

                    u8 actually_clone = UR(4);
                    u32 clone_from, clone_to, clone_len;
                    u8 *new_buf;

                    if (actually_clone) {

                        clone_len = choose_block_len(temp_len);
                        clone_from = UR(temp_len - clone_len + 1);

                    } else {

                        clone_len = choose_block_len(HAVOC_BLK_XL);
                        clone_from = 0;
                    }

                    clone_to = UR(temp_len);

                    new_buf = ck_alloc_nozero(temp_len + clone_len);

                    /* Head */

                    memcpy(new_buf, out_buf, clone_to);

                    /* Inserted part */

                    if (actually_clone)
                        memcpy(new_buf + clone_to, out_buf + clone_from,
                               clone_len);
                    else
                        memset(new_buf + clone_to,
                               UR(2) ? UR(256) : out_buf[UR(temp_len)],
                               clone_len);

                    /* Tail */
                    memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                           temp_len - clone_to);

                    ck_free(out_buf);
                    out_buf = new_buf;
                    temp_len += clone_len;
                }

                break;

            case 14: {

                /* Overwrite bytes with a randomly selected chunk (75%) or fixed
                   bytes (25%). */

                u32 copy_from, copy_to, copy_len;

                if (temp_len < 2)
                    break;

                copy_len = choose_block_len(temp_len - 1);

                copy_from = UR(temp_len - copy_len + 1);
                copy_to = UR(temp_len - copy_len + 1);

                if (UR(4)) {

                    if (copy_from != copy_to)
                        memmove(out_buf + copy_to, out_buf + copy_from,
                                copy_len);

                } else
                    memset(out_buf + copy_to,
                           UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);

                break;
            }

                /* Values 15 and 16 can be selected only if there are any extras
                   present in the dictionaries. */

            case 15: {

                /* Overwrite bytes with an extra. */

                if (!extras_cnt || (a_extras_cnt && UR(2))) {

                    /* No user-specified extras or odds in our favor. Let's use
                       an auto-detected one. */

                    u32 use_extra = UR(a_extras_cnt);
                    u32 extra_len = a_extras[use_extra].len;
                    u32 insert_at;

                    if (extra_len > temp_len)
                        break;

                    insert_at = UR(temp_len - extra_len + 1);
                    memcpy(out_buf + insert_at, a_extras[use_extra].data,
                           extra_len);

                } else {

                    /* No auto extras or odds in our favor. Use the dictionary.
                     */

                    u32 use_extra = UR(extras_cnt);
                    u32 extra_len = extras[use_extra].len;
                    u32 insert_at;

                    if (extra_len > temp_len)
                        break;

                    insert_at = UR(temp_len - extra_len + 1);
                    memcpy(out_buf + insert_at, extras[use_extra].data,
                           extra_len);
                }

                break;
            }

            case 16: {

                u32 use_extra, extra_len, insert_at = UR(temp_len + 1);
                u8 *new_buf;

                /* Insert an extra. Do the same dice-rolling stuff as for the
                   previous case. */

                if (!extras_cnt || (a_extras_cnt && UR(2))) {

                    use_extra = UR(a_extras_cnt);
                    extra_len = a_extras[use_extra].len;

                    if (temp_len + extra_len >= MAX_FILE)
                        break;

                    new_buf = ck_alloc_nozero(temp_len + extra_len);

                    /* Head */
                    memcpy(new_buf, out_buf, insert_at);

                    /* Inserted part */
                    memcpy(new_buf + insert_at, a_extras[use_extra].data,
                           extra_len);

                } else {

                    use_extra = UR(extras_cnt);
                    extra_len = extras[use_extra].len;

                    if (temp_len + extra_len >= MAX_FILE)
                        break;

                    new_buf = ck_alloc_nozero(temp_len + extra_len);

                    /* Head */
                    memcpy(new_buf, out_buf, insert_at);

                    /* Inserted part */
                    memcpy(new_buf + insert_at, extras[use_extra].data,
                           extra_len);
                }

                /* Tail */
                memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                       temp_len - insert_at);

                ck_free(out_buf);
                out_buf = new_buf;
                temp_len += extra_len;

                break;
            }
            }
        }

        if (common_fuzz_stuff(argv, out_buf, temp_len))
            goto abandon_entry;

        /* out_buf might have been mangled a bit, so let's restore it to its
           original size and shape. */

        if (temp_len < len)
            out_buf = ck_realloc(out_buf, len);
        temp_len = len;
        memcpy(out_buf, in_buf, len);

        /* If we're finding new stuff, let's run for a bit longer, limits
           permitting. */

        if (queued_paths != havoc_queued) {

            if (perf_score <= HAVOC_MAX_MULT * 100) {
                stage_max *= 2;
                perf_score *= 2;
            }

            havoc_queued = queued_paths;
        }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    if (!splice_cycle) {
        stage_finds[STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt;
        stage_cycles[STAGE_HAVOC] += stage_max;
    } else {
        stage_finds[STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt;
        stage_cycles[STAGE_SPLICE] += stage_max;
    }

#ifndef IGNORE_FINDS

    /************
     * SPLICING *
     ************/

    /* This is a last-resort strategy triggered by a full round with no
       findings. It takes the current input file, randomly selects another
       input, and splices them together at some offset, then relies on the havoc
       code to mutate that blob. */

retry_splicing:

    if (use_splicing && splice_cycle++ < SPLICE_CYCLES && queued_paths > 1 &&
        queue_cur->len > 1) {

        struct queue_entry *target;
        u32 tid, split_at;
        u8 *new_buf;
        s32 f_diff, l_diff;

        /* First of all, if we've modified in_buf for havoc, let's clean that
           up... */

        if (in_buf != orig_in) {
            ck_free(in_buf);
            in_buf = orig_in;
            len = queue_cur->len;
        }

        /* Pick a random queue entry and seek to it. Don't splice with yourself.
         */

        do {
            tid = UR(queued_paths);
        } while (tid == current_entry);

        splicing_with = tid;
        target = queue;

        while (tid >= 100) {
            target = target->next_100;
            tid -= 100;
        }
        while (tid--)
            target = target->next;

        /* Make sure that the target has a reasonable length. */

        while (target && (target->len < 2 || target == queue_cur)) {
            target = target->next;
            splicing_with++;
        }

        if (!target)
            goto retry_splicing;

        /* Read the testcase into a new buffer. */

        fd = open(target->fname, O_RDONLY);

        if (fd < 0)
            PFATAL("Unable to open '%s'", target->fname);

        new_buf = ck_alloc_nozero(target->len);

        ck_read(fd, new_buf, target->len, target->fname);

        close(fd);

        /* Find a suitable splicing location, somewhere between the first and
           the last differing byte. Bail out if the difference is just a single
           byte or so. */

        locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

        if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
            ck_free(new_buf);
            goto retry_splicing;
        }

        /* Split somewhere between the first and last differing byte. */

        split_at = f_diff + UR(l_diff - f_diff);

        /* Do the thing. */

        len = target->len;
        memcpy(new_buf, in_buf, split_at);
        in_buf = new_buf;

        ck_free(out_buf);
        out_buf = ck_alloc_nozero(len);
        memcpy(out_buf, in_buf, len);

        goto havoc_stage;
    }

#endif /* !IGNORE_FINDS */

    ret_val = 0;

abandon_entry:

    splicing_with = -1;

    /* Update pending_not_fuzzed count if we made it through the calibration
       cycle and have not seen this entry before. */

    if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed) {
        queue_cur->was_fuzzed = 1;
        pending_not_fuzzed--;
        if (queue_cur->favored)
            pending_favored--;
    }

    munmap(orig_in, queue_cur->len);

    if (in_buf != orig_in)
        ck_free(in_buf);
    ck_free(out_buf);
    ck_free(eff_map);

    return ret_val;

#undef FLIP_BIT
}
#endif

static u32 sync_interval_cnt = 0;

u8 libafl_fuzz_one(void) {
    char *argv[] = {""};

    u8 skipped_fuzz;

    cull_queue();

    if (!queue_cur) {
        queue_cycle++;
        current_entry = 0;
        cur_skipped_paths = 0;
        queue_cur = queue;

        while (seek_to) {
            current_entry++;
            seek_to--;
            queue_cur = queue_cur->next;
        }

        show_stats();

        if (not_on_tty) {
            ACTF("Entering queue cycle %llu.", queue_cycle);
            fflush(stdout);
        }

        /* If we had a full queue cycle with no new finds, try
           recombination strategies next. */

        if (queued_paths == prev_queued) {

            if (use_splicing)
                cycles_wo_finds++;
            else
                use_splicing = 1;

        } else
            cycles_wo_finds = 0;

        prev_queued = queued_paths;

        if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
            sync_fuzzers(argv);
    }

#ifdef USE_AFL_FUZZ_ONE
    skipped_fuzz = fuzz_one(argv);
#else
    skipped_fuzz = _fuzz_one(argv);
#endif

    if (sync_id && !skipped_fuzz) {
        if (!(sync_interval_cnt++ % SYNC_INTERVAL))
            sync_fuzzers(argv);
    }

    if (!stop_soon && exit_1)
        stop_soon = 2;

    if (!stop_soon) {
        queue_cur = queue_cur->next;
        current_entry++;
    }

    return stop_soon;
}

void libafl_destroy(void) {
    if (queue_cur)
        show_stats();

    write_bitmap();
    write_stats_file(0, 0, 0);
    save_auto();

    fclose(plot_file);
    destroy_queue();
    destroy_extras();

    if (sync_id) {
        free(sync_id);
    }
}
