#include "hw_malloc.h"

struct chunk_header bin[7];
struct chunk_header *start_brk = NULL;
struct chunk_header *end_brk = NULL;

static void *shift(void *const chunk, const long long size)
{
	return chunk + size;
}

static struct chunk_header *regular(struct chunk_header *const chunk)
{
	if ((void *)chunk < (void *)start_brk) {
		return shift(chunk, 65536);
	} else if ((void *)chunk >= (void *)start_brk + 65536) {
		return shift(chunk, -(65536));
	} else {
		return chunk;
	}
}

static struct chunk_header *prev_header(struct chunk_header *const chunk)
{
	return regular(shift(chunk, -(chunk->pre_chunk_size)));
}

static struct chunk_header *next_header(struct chunk_header *const chunk)
{
	return regular(shift(chunk, chunk->chunk_size));
}

static int chunk_is_free(struct chunk_header_t *const chunk)
{
	return next_header(chunk)->prev_free_flag == 1;
}

static int set_chunk_free_flag(struct chunk_header_t *const chunk, int _free)
{
	next_header(chunk)->prev_free_flag = _free;
}

static int in_range(struct chunk_header *const chunk)
{
	return (((void *)start_brk <= (void *)chunk) &&
	        ((void *)chunk + 40 <=
	         (void *)start_brk + 65536));

}

static int can_merge_next(struct chunk_header *const chunk)
{
	if (next_header(chunk) > chunk &&
	    chunk_is_free(next_header(chunk)) &&
	    chunk_is_free(chunk)) {
		return 1;
	}
	return 0;
}

static void merge_next(struct chunk_header *const chunk)
{
	delete_list(chunk);
	delete_list(next_header(chunk));
	chunk->chunk_size = chunk->chunk_size + next_header(chunk)->chunk_size;
	next_header(chunk)->pre_chunk_size = chunk->chunk_size;
	add_list(chunk);
}

/*static int is_header(struct chunk_header *const chunk)
{
	void *bound = shift(start_brk, 65536);
	struct chunk_header *idx = start_brk;

	while ((void *)idx < bound && idx <= chunk) {
		if (idx == chunk) {
			return 1;
		}
		idx = shift(idx, idx->chunk_size);
	}

	return 0;
}*/

void add_list(struct chunk_header *chunk)
{
	int bin_no;
	if (chunk->chunk_size == 48) bin_no = 0;
	else if (chunk->chunk_size == 56) bin_no = 1;
	else if (chunk->chunk_size == 64) bin_no = 2;
	else if (chunk->chunk_size == 72) bin_no = 3;
	else if (chunk->chunk_size == 80) bin_no = 4;
	else if (chunk->chunk_size == 88) bin_no = 5;
	else bin_no = 6;

	if (bin_no == 6) {	//largest at bin[6].next
		struct chunk_header *ptr = bin[6].next;
		while (ptr != &bin[6] && ptr->chunk_size >= chunk->chunk_size)
			ptr = ptr->next;
		ptr->prev->next = chunk;
		chunk->prev = ptr->prev;
		chunk->next = ptr;
		ptr->prev = chunk;
	} else {	//newest at bin[].prev
		bin[bin_no].prev->next = chunk;
		chunk->prev = bin[bin_no].prev;
		chunk->next = &bin[bin_no];
		bin[bin_no].prev = chunk;
	}
	return;
}

void delete_list(struct chunk_header *chunk)
{
	chunk->prev->next = chunk->next;
	chunk->next->prev = chunk->prev;
	chunk->prev = chunk;
	chunk->next = chunk;
	return;
}

void *hw_malloc(size_t bytes)
{
	struct chunk_header *allocated_chunk = NULL;
	struct chunk_header *free_chunk = NULL;
	struct chunk_header *next_chunk = NULL;
	//adjust chunk size to multiple of 8
	int size = bytes + sizeof(struct chunk_header);
	if (size % 8 != 0)
		size = 8 * ((size / 8) + 1);
	//first time only
	if (start_brk == NULL) {
		//create heap
		start_brk = sbrk(65536);
		end_brk = sbrk(0);
		//create bin
		int i;
		for (i = 0; i < 7; i++) {
			bin[i].prev = &bin[i];
			bin[i].next = &bin[i];
			bin[i].chunk_size = 0;
			bin[i].pre_chunk_size = 0;
			bin[i].prev_free_flag = 0;
		}

		allocated_chunk = start_brk;
		free_chunk = (long long int)allocated_chunk + size;

		allocated_chunk->chunk_size = size;
		next_header(allocated_chunk)->pre_chunk_size = allocated_chunk->chunk_size;

		free_chunk->chunk_size = (long long int)end_brk - (long long int)free_chunk;
		next_header(free_chunk)->pre_chunk_size = free_chunk->chunk_size;

		free_chunk->prev = NULL;
		free_chunk->next = NULL;
		set_chunk_free_flag(allocated_chunk, 0);
		set_chunk_free_flag(free_chunk, 1);
		add_list(free_chunk);
		return (long long int)allocated_chunk + sizeof(struct chunk_header);
	}
	//if fixed size free chunk already exist
	int i;
	for (i = 0; i < 6; i++) {
		if ((i == 0 && size == 48) ||
		    (i == 1 && size == 56) ||
		    (i == 2 && size == 64) ||
		    (i == 3 && size == 72) ||
		    (i == 4 && size == 80) ||
		    (i == 5 && size == 88)) {
			if (bin[i].next != &bin[i]) {	//not empty
				allocated_chunk = bin[i].next;
				set_chunk_free_flag(allocated_chunk, 0);
				delete_list(allocated_chunk);
				return (long long int)allocated_chunk + sizeof(struct chunk_header);
			}
		}
	}
	//if no fixed chunk can use or larger than 88
	struct chunk_header *ptr = bin[6].prev;
	while (ptr != &bin[6] && ptr->chunk_size < size)
		ptr = ptr->prev;
	while (ptr != &bin[6] && ptr->prev->chunk_size == ptr->chunk_size)
		ptr = ptr->prev;
	allocated_chunk = ptr;
	//split
	if (allocated_chunk->chunk_size > 88
	    && (allocated_chunk->chunk_size - size >= 48)) {
		free_chunk = (struct chunk_header*)((void*)allocated_chunk + size);

		free_chunk->chunk_size = allocated_chunk->chunk_size - size;
		allocated_chunk->chunk_size = size;
		free_chunk->pre_chunk_size = size;
		next_header(free_chunk)->pre_chunk_size = free_chunk->chunk_size;

		free_chunk->prev = NULL;
		free_chunk->next = NULL;
		set_chunk_free_flag(free_chunk, 1);
		add_list(free_chunk);
	}
	set_chunk_free_flag(allocated_chunk, 0);
	delete_list(allocated_chunk);
	return (long long int)allocated_chunk + sizeof(struct chunk_header);
}

int hw_free(void *mem)
{
	struct chunk_header *chunk = (long long int)mem - sizeof(struct chunk_header);

	if (chunk < start_brk || chunk >= end_brk)	//out of range
		return 0;
	struct chunk_header *ptr = start_brk;
	while (ptr < chunk)
		ptr = (long long int)ptr + ptr->chunk_size;
	if (ptr != chunk || chunk_is_free(chunk))
		return 0;

	set_chunk_free_flag(chunk, 1);
	add_list(chunk);
	if (can_merge_next(chunk)) {
		merge_next(chunk);
	}
	if (can_merge_next(prev_header(chunk))) {
		merge_next(prev_header(chunk));
	}
	return 1;
}

void *get_start_sbrk(void)
{
	return start_brk;
}

void print_bin(int bin_no)
{
	struct chunk_header *ptr = bin[bin_no].next;
	while (ptr != &bin[bin_no]) {
		printf("0x%08x--------%lld\n", (long long int)ptr - (long long int)start_brk,
		       ptr->chunk_size);
		ptr = ptr->next;
	}
	return;
}
