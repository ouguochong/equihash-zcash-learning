#ifndef __BUCKET_SORT_H__
#define __BUCKET_SORT_H__

#define BUCKET_SORT 0

#define LOCAL_FILE_1	"local_file_1"
#define LOCAL_FILE_2	"local_file_2"

//#define BUCKET_MAX_NUM	do{ ((2 << 20) % 22 == 0)?((2 << 20) / 22):((2 << 20) / 22 + 1)}while(0)
#define BUCKET_MAX_NUM	47663
#define BUCKET_DEPTH	128

typedef struct bucket{
	int line_num;
	int index[128];
	uint8_t bucket_item[128][30*2+1];
}bucket_t;

void bucket_sort_init();
void bucket_sort_exit();
void bucket_sort_output_file_1(uint8_t* tmpHash, const size_t hashOutput, int g);
int bucket_sort_pack_hash_to_buckets2(uint8_t *tmpHash, const size_t hashOutput, int g);
int bucket_sort_output_file_2();

#endif
