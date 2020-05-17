// TODO: obsolete

#ifndef LIBAGAMOTTO_SNAPSHOT_H
#define LIBAGAMOTTO_SNAPSHOT_H

#include <inttypes.h>

#define MAX_SNAPSHOTS 1024
#define MAX_SNAPSHOT_SIZE_TOTAL 512 // MiB
#define MAX_SNAPSHOT_SIZE_EACH 1    // MiB

// Probably maintain correspondence between input and snapshot.
// Multiple inputs can point to a single snapshot.

int vmfuzzer_savevm(int, const uint8_t *);

int vmfuzzer_loadvm(const uint8_t *);

int vmfuzzer_purge_unused_snapshots();

#endif