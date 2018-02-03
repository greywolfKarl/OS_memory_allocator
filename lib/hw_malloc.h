#ifndef HW_MALLOC_H
#define HW_MALLOC_H

#include <stddef.h>
#include <inttypes.h>
#include <unistd.h>

typedef struct chunk_header* chunk_ptr_t;
typedef long long int chunk_size_t;
typedef long long int chunk_flag_t;

struct chunk_header {
	chunk_ptr_t prev;
	chunk_ptr_t next;
	chunk_size_t chunk_size;
	chunk_size_t pre_chunk_size;
	chunk_flag_t prev_free_flag;
};

extern void *hw_malloc(size_t bytes);
extern int hw_free(void *mem);
extern void *get_start_sbrk(void);

#endif
