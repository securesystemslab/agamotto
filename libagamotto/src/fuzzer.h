#ifndef LIBAGAMOTTO_FUZZER_H
#define LIBAGAMOTTO_FUZZER_H

extern char monitor_socket_file[];

int periscope_init_syz_fuzzer(char **, char *, char *, char *, char *, int *,
                              int *, int *, char *);

void periscope_pre_qemu_init(int *, int *);
void periscope_post_qemu_init(void);

#endif