#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <agamotto.h>

#define EXEC_BUFFER_SIZE (2 << 20)
#define OUTPUT_SIZE (16 << 20)

const int kInFd = 3;
const int kOutFd = 4;

static int file_idx = 0;

typedef struct {
	uint64_t pfn : 54;
	unsigned int soft_dirty : 1;
	unsigned int file_page : 1;
	unsigned int swapped : 1;
	unsigned int present : 1;
} PagemapEntry;

static int pagemap_get_entry(PagemapEntry* entry, int pagemap_fd, uintptr_t vaddr)
{
	size_t nread;
	ssize_t ret;
	uint64_t data;
	uintptr_t vpn;

	vpn = vaddr / sysconf(_SC_PAGE_SIZE);
	nread = 0;
	while (nread < sizeof(data)) {
		ret = pread(pagemap_fd, &data, sizeof(data) - nread,
			    vpn * sizeof(data) + nread);
		nread += ret;
		if (ret <= 0) {
			printf("failed to pread\n");
			return -1;
		}
	}

	entry->pfn = data & (((uint64_t)1 << 54) - 1);
	entry->soft_dirty = (data >> 54) & 1;
	entry->file_page = (data >> 61) & 1;
	entry->swapped = (data >> 62) & 1;
	entry->present = (data >> 63) & 1;
	return 0;
}

static uint64_t get_phys_addr(pid_t pid, void* vaddr)
{
	char pagemap_file[BUFSIZ];
	int pagemap_fd;

	snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%ju/pagemap", (uintmax_t)pid);
	pagemap_fd = open(pagemap_file, O_RDONLY);
	if (pagemap_fd < 0) {
		printf("failed to open %s\n", pagemap_file);
		return 0;
	}

	PagemapEntry entry;
	if (pagemap_get_entry(&entry, pagemap_fd, (uintptr_t)vaddr)) {
		return 0;
	}

	close(pagemap_fd);

	return (entry.pfn * sysconf(_SC_PAGE_SIZE)) + ((uintptr_t)vaddr % sysconf(_SC_PAGE_SIZE));
}

static void printk(const char* fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	//char msg[1024];
	//snprintf(msg, sizeof(msg), fmt, args);

	int kmsg_fd = open("/dev/kmsg", O_WRONLY);
	if (kmsg_fd > 0) {
		//printf("printk fd=%d msg=%s", kmsg_fd, msg);
		//write(kmsg_fd, msg, strlen(msg) + 1);
		dprintf(kmsg_fd, fmt, args);
		close(kmsg_fd);
	} else {
		printf("open /dev/kmsg failed with errno=%d\n", errno);
	}

	va_end(args);
}

static char* create_mem_mapped_file(size_t sz, int* out_fd)
{
	int fd;
	char* ptr;

	char file_name[80];
	sprintf(file_name, "/shm-syzkaller-%d", file_idx++);

	fd = shm_open(file_name, O_RDWR | O_CREAT | O_TRUNC, 0644);

	if (fd <= 0) {
		printf("open failed\n");
		return NULL;
	}

	printf("new_fd=%d\n", fd);

	if (out_fd) {
		*out_fd = fd;
	}

	if (lseek(fd, sz - 1, SEEK_SET) == -1) {
		printf("lseek failed\n");
		return NULL;
	}

	if (write(fd, "", 1) != 1) {
		printf("write failed\n");
		return NULL;
	}

	ptr = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	memset(ptr, 0xab, sz);

	return ptr;
}

#define OPEN_IN_PIPE
#undef OPEN_IN_PIPE
#define OPEN_OUT_PIPE
#undef OPEN_OUT_PIPE

static int create_virtio_pipes(int* in_fd, int* out_fd, int* err_fd)
{
#ifdef OPEN_IN_PIPE
	char* in_file = "/dev/virtio-ports/serial0";
#endif
#ifdef OPEN_OUT_PIPE
	char* out_file = "/dev/virtio-ports/serial1";
#endif
	char* err_file = "/dev/virtio-ports/serial2";
	int fd;

#ifdef OPEN_IN_PIPE
	fd = open(in_file, O_RDONLY);
	if (fd <= 0) {
		printf("opening stdout failed\n");
		return -1;
	}

	if (dup2(fd, 0) < 0) {
		printf("dup to stdin failed\n");
		return -1;
	}

	close(fd);
#endif

	*in_fd = 0;

#ifdef OPEN_OUT_PIPE
	fd = open(out_file, O_WRONLY | O_SYNC);
	if (fd <= 0) {
		printf("opening stdout failed\n");
		return -1;
	}

	if (dup2(fd, 1) < 0) {
		printf("dup to stdout failed\n");
		return -1;
	}

	close(fd);
#endif

	*out_fd = 1;

	fd = open(err_file, O_WRONLY | O_SYNC);
	if (fd <= 0) {
		printf("opening stderr failed\n");
		return -1;
	}

	// make stderr go to err_file
	if (dup2(fd, 2) < 0) {
		printf("dup to stderr failed\n");
		return -1;
	}

	close(fd);

	*err_fd = 2;

	return 0;
}

#define NOSHMEM 0

static int make_env()
{
	int in_fd, out_fd, err_fd;

#if 1 // pipes

#if !NOSHMEM
	char* host_test = getenv("HOST_TEST");

	int in_shm_fd = open("/dev/uio0", O_RDWR | O_SYNC); // in
	int out_shm_fd = open("/dev/uio1", O_RDWR | O_SYNC); // out

	if (in_shm_fd != kInFd || out_shm_fd != kOutFd) {
		perror("unexpected file descriptors\n");
		return -1;
	}

	if (host_test) {
		printf("in_shm_fd=%d out_shm_id=%d", in_shm_fd, out_shm_fd);

		char* map = (char*)mmap(0, 2 << 20, PROT_READ | PROT_WRITE, MAP_SHARED, in_shm_fd, 1 * getpagesize());
		if (map == MAP_FAILED) {
			perror("map of kInFd: failed\n");
			return -1;
		}
		printf("map of kInFd: success\n");
		munmap(map, 2 << 20);
	}

#endif

	if (create_virtio_pipes(&in_fd, &out_fd, &err_fd) != 0) {
		return -1;
	}

#if 1
	// TODO: hypercall
#else
	// handshake with fuzzer running in host
	uint32_t val = 0x0;
	int res;
	if ((res = read(in_fd, &val, 4)) != 4) {
		printf("read from in_fd failed\n");
		printk("### read from in_fd failed\n");
	}
	printf("read 0x%x\n", val);
	printk("### read 0x%x\n", val);

	if (val != 0xdeaddead) {
		return -1;
	}

	val = 0xbeefbeef;
	if ((res = write(out_fd, &val, 4)) != 4) {
		printf("write to out_fd failed\n");
		printk("### write to out_fd failed\n");
		return -1;
	}
	printf("written 0x%x\n", val);
	printk("### written 0x%x\n", val);
#endif

	if (in_fd != 0 || out_fd != 1 || err_fd != 2) {
		printf("unexpected file descriptors\n");
		return -1;
	}

#else
	char* in_ptr;
	char* out_ptr;

	in_ptr = create_mem_mapped_file(EXEC_BUFFER_SIZE, &in_fd);
	out_ptr = create_mem_mapped_file(OUTPUT_SIZE, &out_fd);

	if (!in_ptr || !out_ptr) {
		printf("failed to mmap file descriptors\n");
		return -1;
	}

	int pid = getpid();
	uint64_t in_phys_ptr = get_phys_addr(pid, in_ptr);
	uint64_t out_phys_ptr = get_phys_addr(pid, out_ptr);

	char* host_test = getenv("HOST_TEST");
	if (!host_test) {
		agamotto_kvm_hypercall3(HC_AGAMOTTO_DEBUG, 3, in_phys_ptr);
		agamotto_kvm_hypercall3(HC_AGAMOTTO_DEBUG, 4, out_phys_ptr);
	}

	printf("in=0x%lx out=0x%lx\n", in_phys_ptr, out_phys_ptr);

	if (in_fd != kInFd || out_fd != kOutFd || err_fd != 2) {
		printf("unexpected file descriptors\n");
		return -1;
	}
#endif

	return 0;
}

int main(int argc, char** argv)
{
	// TODO: support simple executor command, e.g., revision

	if (make_env() == 0) {
		printf("executing syz-executor...\n");
		printk("### executing syz-executor...\n");

		argv[0] = "syz-executor";
		execv("/syz-executor", argv);

		printf("execv exited with error %d\n", errno);
	} else {
		printf("syz-executor env setup failed.\n");
		printk("### syz-executor env setup failed.\n");
	}

	return 0;
}
