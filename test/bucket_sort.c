#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "bucket_sort.h"

static int debug1 = 1;
#define D(x...) if (debug1) fprintf(stderr, x);

FILE *fp_file_1 = NULL;
FILE *fp_file_2 = NULL;
bucket_t *buckets_buff = NULL;

static void __bin2hex(char *s, const unsigned char *p, size_t len)
{
    int i;
    static const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    for (i = 0; i < (int)len; i++)
    {
        *s++ = hex[p[i] >> 4];
        *s++ = hex[p[i] & 0xF];
    }
    *s++ = '\0';
}

/* Returns a malloced array string of a binary value of arbitrary length. The
 * array is rounded up to a 4 byte size to appease architectures that need
 * aligned array  sizes */
static char *bin2hex(const unsigned char *p, size_t len)
{
    size_t slen;
    char *s;

    slen = len * 2 + 1;
    if (slen % 4)
        slen += 4 - (slen % 4);
    s = calloc(slen, 1);

    __bin2hex(s, p, len);

    return s;
}


void bucket_sort_init()
{
	fp_file_1 = fopen(LOCAL_FILE_1, "w+");
	if (fp_file_1 == NULL) {
		printf("open %s error\n", LOCAL_FILE_1);
		goto failed;
	}
	fp_file_2 = fopen(LOCAL_FILE_2, "w+");
	if (fp_file_2 == NULL) {
		printf("open %s error\n", LOCAL_FILE_2);
		goto failed;
	}

	buckets_buff = (bucket_t *)malloc(sizeof(bucket_t) * BUCKET_MAX_NUM);
	if (buckets_buff == NULL){
		D("malloc bucket_buff failed\n");
		goto failed;
	}
	memset((uint8_t *)buckets_buff, 0, sizeof(bucket_t) * BUCKET_MAX_NUM);
	return;

failed:
	if(fp_file_1 != NULL)
		fclose(fp_file_1);
	if(fp_file_2 != NULL)
		fclose(fp_file_2);
	if(buckets_buff != NULL)
		free(buckets_buff);
}

void bucket_sort_exit()
{
	if(fp_file_1 != NULL)
		fclose(fp_file_1);
	if(fp_file_2 != NULL)
		fclose(fp_file_2);
	if(buckets_buff != NULL)
		free(buckets_buff);
}

void bucket_sort_output_file_1(uint8_t* tmpHash, const size_t hashOutput, int g)
{
	char *hex_buff = NULL;
	char *hex_buff2 = NULL;
	
	hex_buff = bin2hex(tmpHash, hashOutput/2);
	hex_buff2 = bin2hex(tmpHash+hashOutput/2, hashOutput/2);
	if (hex_buff != NULL && hex_buff2 != NULL) {
		fprintf(fp_file_1, "%s   %08x\n", hex_buff, g*2);
		fprintf(fp_file_1, "%s   %08x\n", hex_buff2, g*2+1);
	} else {
		D("error:hex_buff is NULL\n");
		D("\t\t error:hex_buff is NULL\n");
		D("\t\t\t\t error:hex_buff is NULL\n");
		exit(-1);
	}
	free(hex_buff);
	free(hex_buff2);
}

int bucket_sort_pack_hash_to_buckets2(uint8_t *tmpHash, const size_t hashOutput, int g)
{
	uint8_t pre20bits[3] = {0};
	uint32_t pre20bits_value = 0;
	int bucket_index = 0;
	int line_index = 0;
	char *hex_buff = NULL;
	uint8_t tmp_tmpHash[25] = {0};

	for (int i=0;i<2;i++)
	{
		memcpy(tmp_tmpHash, tmpHash+i*hashOutput/2, hashOutput/2);
		memcpy(pre20bits, tmp_tmpHash, 3);
		pre20bits_value = ((uint32_t)pre20bits[0] << 12) | ((uint32_t)pre20bits[1] << 4) | (((uint32_t)pre20bits[2] & 0xf0) >> 4);
		bucket_index = pre20bits_value / 22;
		line_index = buckets_buff[bucket_index].line_num;
		if (line_index < BUCKET_DEPTH && bucket_index < BUCKET_MAX_NUM) {
			hex_buff = bin2hex(tmp_tmpHash, hashOutput/2);
			memcpy(buckets_buff[bucket_index].bucket_item[line_index] ,hex_buff, hashOutput+1);
			D("[%d][%d] %s\n", bucket_index, buckets_buff[bucket_index].line_num, buckets_buff[bucket_index].bucket_item[line_index]);
			free(hex_buff);
			buckets_buff[bucket_index].index[line_index] = g*2 + i;
			buckets_buff[bucket_index].line_num++;
		} else {
			D("[%d][%d]\n", bucket_index, line_index);
		}
	}
}

int bucket_sort_output_file_2()
{

	char bucket_item[25*2+1] = {'0'};
	memset(bucket_item, '0', sizeof(bucket_item));
	bucket_item[25*2] = '\0';

	for (int i=0; i<BUCKET_MAX_NUM; i++)
	{
		for (int j=0; j<BUCKET_DEPTH; j++)
		{
			if (j < buckets_buff[i].line_num)
				fprintf(fp_file_2, "%s   %08x\n", buckets_buff[i].bucket_item[j], buckets_buff[i].index[j]);
			else
				fprintf(fp_file_2, "%s   ffffffff\n", bucket_item);
		}
	}
}

