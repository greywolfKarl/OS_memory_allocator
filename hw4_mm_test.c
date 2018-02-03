#include "hw4_mm_test.h"

int counter = 0;

int main()
{
	char input[100];
	int size, bin_no;
	int freeee;
	while(fgets(input, 100, stdin) != NULL) {
		++counter;
		//if(counter==1465)
		//printf("zz");
		if(input[0] == 'a') {
			sscanf(input, "alloc %d", &size);
			printf("%010p\n", hw_malloc(size) - get_start_sbrk());
		} else if(input[0] == 'f') {
			sscanf(input, "free %x", &freeee);
			//printf("%x\n", freeee);
			printf("%s\n", hw_free(freeee + get_start_sbrk()) == 1 ? "success" : "fail");
		} else if(input[0] == 'p') {
			sscanf(input, "print bin[%d]", &bin_no);
			print_bin(bin_no);
		} else
			;
	}
	/*printf("chunk_header size: %ld\n", sizeof(struct chunk_header));
	fflush(stdout);
	printf("%p\n", hw_malloc(8));
	fflush(stdout);
	printf("%s\n", hw_free(40) == 1 ? "success" : "fail");
	fflush(stdout);
	printf("start_brk: %p\n", get_start_sbrk());
	fflush(stdout);
	printf("%p\n", hw_malloc(16));
	fflush(stdout);
	printf("%s\n", hw_free(144) == 1 ? "success" : "fail");
	return 0;*/
}
