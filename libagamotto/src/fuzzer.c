#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <libafl.h>
#include <agamotto.h>

#include "fuzzer.h"

// can it be fork-and-exec? would it be better or not?
static pthread_t s_fuzzer_thread;
static pthread_t s_vmfuzzer_io_thread;

static volatile bool s_fuzzer_exiting = false;
static pthread_cond_t fuzzer_init_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t fuzzer_init_cond_mutex = PTHREAD_MUTEX_INITIALIZER;

#define QEMU_MONITOR_UNIX_SOCKET 0

#if QEMU_MONITOR_UNIX_SOCKET
static int mon_fd = -1;
#endif

static int st_pipe[2], ctl_pipe[2];

#if 0
static void *periscope_forksrv_thread_fn(void *arg) {
    s32 res;
    int prev_timed_out;
    int child_pid = 1; // fake child_pid
    int status = 0;

    printf("periscope: fork server thread up and running\n");

    while (1) {
        if ((res = read(ctl_pipe[0], &prev_timed_out, 4)) != 4) {
            printf("read from control pipe failed\n");
        }

#ifdef DEBUG
        printf("returning a fake child...\n");
#endif

        if ((res = write(st_pipe[1], &child_pid, 4)) != 4) {
            printf("write to status pipe failed\n");
        }

        // printf("periscope: new input (%s) generated\n", out_file);

        // usleep(100 * 1000);

        if ((res = write(st_pipe[1], &status, 4)) != 4) {
            printf("write to status pipe failed\n");
        }
    }

    return NULL;
}
#endif

static void *periscope_fuzzer_thread_fn(void *param) {
    pthread_mutex_lock(&fuzzer_init_cond_mutex);
    pthread_cond_signal(&fuzzer_init_cond);
    pthread_mutex_unlock(&fuzzer_init_cond_mutex);

#if 0
    pthread_t forksrv;
    ret = pthread_create(&forksrv, NULL, periscope_forksrv_thread_fn, NULL);
    if (ret < 0) {
        return NULL;
    }
#endif

    libafl_perform_dry_run();

    while (!s_fuzzer_exiting) {
        u8 stop_soon;
        stop_soon = libafl_fuzz_one();
        if (stop_soon) {
            printf("periscope: stop soon flag set\n");
            break;
        }
    }

    libafl_destroy();

#if 0
    pthread_join(forksrv, NULL);
#endif

#if QEMU_MONITOR_UNIX_SOCKET
    int rc;

    const char *cmd = "list snapshots"; // list the VM snapshots

    printf("Cmd: %s\n", cmd);
    rc = write(mon_fd, cmd, sizeof(cmd));
    if (rc != sizeof(cmd)) {
        printf("cmd partially written\n");
    }
    rc = 0;

    while (!s_fuzzer_exiting) {
        int wr_bytes = write(mon_fd, cmd, sizeof(cmd));
        if (wr_bytes != sizeof(cmd)) {
            printf("wr error\n");
            break;
        }

        // printf("vmfuzzer heartbeat\n");

        usleep(100 * 10000);
    }
#endif

    return NULL;
}

static void *periscope_io_thread_fn(void *arg) {
#if QEMU_MONITOR_UNIX_SOCKET
    char buf[1024] = {0};

    int rc;
    int rd_bytes = 0;

    rc = read(mon_fd, buf, 1024);

    while (rc > 0 && !s_fuzzer_exiting) {
        rd_bytes += rc;

        for (unsigned i = 0; i < rc; i++) {
            printf("%c", buf[i]);
        }
        memset(buf, 0, sizeof(buf));
        rc = read(mon_fd, buf, 1024);
        // printf("rc = %d\n", rc);
    }
#endif

    return NULL;
}

int periscope_init_syz_fuzzer(char **qemu_argv, char *syz_fuzzer_path,
                              char *syz_fuzzer_argv, char *syz_fuzzer_executor,
                              char *syz_fuzzer_index, int *out_st_pipe,
                              int *out_ctl_pipe, int *out_shm_id,
                              char *fifo_out) {
    if (pipe(st_pipe) || pipe(ctl_pipe)) {
        return -1;
    }

    *out_st_pipe = st_pipe[1];
    *out_ctl_pipe = ctl_pipe[0];

    int kCoverSize = 256 << 10;

#ifdef OPEN_SHM
#if 0
    *out_shm_id = open("/dev/shm/syzkaller", O_CREAT | O_RDWR | O_TRUNC, 0600);
#else
    char *shm_id_str = "/syzkaller";
    *out_shm_id = shm_open(shm_id_str, O_CREAT | O_RDWR | O_TRUNC, 0600);
#endif
    ftruncate(*out_shm_id, (kCoverSize * sizeof(uintptr_t)) * 2);
#endif

    if (fork() == 0) {
        int pid = getpid();
        printf("periscope: child pid=%d syz-fuzzer=%s %s syz-executor=%s...\n",
               pid, syz_fuzzer_path, syz_fuzzer_argv, syz_fuzzer_executor);

        prctl(PR_SET_PDEATHSIG, SIGHUP);

#ifdef OPEN_IN_PIPE
        int in_pipe = open("/tmp/serial0.in", O_WRONLY | O_SYNC);
#endif
#ifdef OPEN_OUT_PIPE
        int out_pipe = open("/tmp/serial1.out", O_RDONLY);
#endif
        int err_pipe = 0;
        if (fifo_out) {
            err_pipe = open(fifo_out, O_RDONLY);
        }
#ifdef OPEN_IN_PIPE
        char in_pipe_str[10 + 1];
        sprintf(in_pipe_str, "%d", in_pipe);
#endif
#ifdef OPEN_OUT_PIPE
        char out_pipe_str[10 + 1];
        sprintf(out_pipe_str, "%d", out_pipe);
#endif
        char err_pipe_str[10 + 1];
        sprintf(err_pipe_str, "%d", err_pipe);

        char st_pipe_str[10 + 1];
        char ctl_pipe_str[10 + 1];
        sprintf(st_pipe_str, "%d", st_pipe[0]);
        sprintf(ctl_pipe_str, "%d", ctl_pipe[1]);

        if (execl(syz_fuzzer_path, "syz-fuzzer", "-executor",
                  syz_fuzzer_executor, "-args", syz_fuzzer_argv, "-st_pipe",
                  st_pipe_str, "-ctl_pipe", ctl_pipe_str,
#ifdef OPEN_IN_PIPE
                  "-in_pipe", in_pipe_str,
#endif
#ifdef OPEN_OUT_PIPE
                  "-out_pipe", out_pipe_str,
#endif
                  "-err_pipe", err_pipe_str,
#ifdef OPEN_SHM
                  "-shm_id", shm_id_str,
#endif
                  "-index", syz_fuzzer_index, NULL) == -1) {
            printf("periscope-child: execv errno=%d\n", errno);
            exit(1);
        }
    } else {
        // parent
    }

    return 0;
}

static int periscope_init_fuzzer(int *out_st_pipe, int *out_ctl_pipe) {
    int ret;
    pthread_attr_t attr;

    if (pipe(st_pipe) || pipe(ctl_pipe)) {
        return -1;
    }

    char *out_file = getenv("__PERISCOPE_OUT_FILE");
    if (!out_file || strlen(out_file) == 0) {
        out_file = "cur";
    }

    char *master_id = getenv("__PERISCOPE_MASTER_ID");
    char *secondary_id = getenv("__PERISCOPE_SECONDARY_ID");
    if (master_id && strlen(master_id)) {
        secondary_id = NULL;
    } else if (secondary_id && strlen(secondary_id)) {
        master_id = NULL;
    } else {
        master_id = NULL;
        secondary_id = NULL;
    }

    *out_st_pipe = st_pipe[1];
    *out_ctl_pipe = ctl_pipe[0];

    char *in_dir = getenv("__PERISCOPE_IN_DIR");
    if (!in_dir || strlen(in_dir) == 0) {
        in_dir = "-";
    }
    char *out_dir = getenv("__PERISCOPE_OUT_DIR");
    if (!out_dir || strlen(out_dir) == 0) {
        out_dir = "out";
    }
    char *dict_dir = getenv("__PERISCOPE_DICT_DIR");
    if (!dict_dir || strlen(dict_dir) == 0) {
        dict_dir = "";
    }

    unsigned int seed = -1;
    char *seed_str = getenv("__PERISCOPE_AFL_SEED");
    if (seed_str) {
        sscanf(seed_str, "%d", &seed);
    } else {
        printf("periscope: seed id not given\n");
    }

    u8 opt_n = false;
    u8 opt_d = false;
    u8 ok =
        libafl_setup(in_dir, out_dir, dict_dir, out_file, ctl_pipe[1],
                     st_pipe[0], opt_n, opt_d, master_id, secondary_id, seed);
    if (!ok) {
        ret = -1;
        goto err;
    }

    ret = pthread_attr_init(&attr);
    if (ret < 0) {
        goto err;
    }

    ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (ret < 0) {
        goto err;
    }

    ret = pthread_create(&s_fuzzer_thread, &attr, periscope_fuzzer_thread_fn,
                         NULL);

    pthread_attr_destroy(&attr);

    pthread_mutex_lock(&fuzzer_init_cond_mutex);
    pthread_cond_wait(&fuzzer_init_cond, &fuzzer_init_cond_mutex);
    pthread_mutex_unlock(&fuzzer_init_cond_mutex);

    printf("periscope: fuzzer initialized.\n");

err:
    return ret;
}

static int initialize_vmfuzzer_io_thread(void) {
    int ret;
    pthread_attr_t attr;

    ret = pthread_attr_init(&attr);
    if (ret < 0) {
        goto err;
    }

    ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (ret < 0) {
        goto err;
    }

    ret = pthread_create(&s_vmfuzzer_io_thread, &attr, periscope_io_thread_fn,
                         NULL);

    pthread_attr_destroy(&attr);

err:
    return ret;
}

static void (*qemu_sigint_handler)(int);

static void vmfuzzer_sigint_handler(int signo) {
    printf("received SIGINT\n");
    qemu_sigint_handler(signo);
}

static void initialize_signal_handler(void) {
    struct sigaction sa;
    struct sigaction old;

    printf("periscope: initializing signal handler\n");

    sigaction(SIGINT, NULL, &old);
    if (old.sa_handler) {
        printf("No existing signal handler\n");
    }
    qemu_sigint_handler = old.sa_handler;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = vmfuzzer_sigint_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
}

void periscope_post_qemu_init(void) {
    printf("periscope: post init...\n");

    initialize_signal_handler();

#if QEMU_MONITOR_UNIX_SOCKET
    struct sockaddr_un addr;
    mon_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (mon_fd == -1) {
        printf("socket creation failed\n");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, monitor_socket_file, sizeof(addr.sun_path) - 1);

    printf("Connecting to socket: %s\n", monitor_socket_file);
    if (connect(mon_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        printf("socket connection failed\n");
    }
#endif

    int ret = initialize_vmfuzzer_io_thread();

    if (ret < 0) {
        printf("initialize vmfuzzer io thread failed.\n");
    }
}

void periscope_pre_qemu_init(int *out_st_pipe, int *out_ctl_pipe) {
    printf("periscope: initializing...\n");

    int ret = periscope_init_fuzzer(out_st_pipe, out_ctl_pipe);

    if (ret < 0) {
        printf("initialie vmfuzzer thread failed.\n");
    }
}

int periscope_mmio_read(unsigned size, uint64_t *out) {
    //
    return 0;
}