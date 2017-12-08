/*
 * Copyright (c) 2016 abc at openwall dot com
 * Copyright (c) 2016 Jack Grigg
 * Copyright (c) 2016 The Zcash developers
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Port to C of C++ implementation of the Equihash Proof-of-Work
 * algorithm from zcashd.
 */

#define _BSD_SOURCE
#define _GNU_SOURCE
#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <blake2.h>
#include <blake2-impl.h>
#include "bucket_sort.h"

#define swap(a, b) \
    do { __typeof__(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

int debug = 1;
#define D(x...) if (debug) fprintf(stderr, x);

static void dump_hex(uint8_t *data, size_t len)
{
    for (int i = 0; i < len; ++i)
        printf("%02x", data[i]);
}

/* Writes Zcash personalization string. */
static void zcashPerson(uint8_t *person, const int n, const int k)
{
    memcpy(person, "ZcashPoW", 8);
    *(uint32_t *)(person +  8) = htole32(n);
    *(uint32_t *)(person + 12) = htole32(k);
}

static void digestInit(blake2b_state *S, const int n, const int k)
{
    blake2b_param P[1];

    memset(P, 0, sizeof(blake2b_param));
    P->fanout        = 1;
    P->depth         = 1;
    P->digest_length = (512 / n) * n / 8;
    zcashPerson(P->personal, n, k);
    blake2b_init_param(S, P);
}

static void ehIndexToArray(const uint32_t i, uint8_t *array)
{
    const uint32_t be_i = htobe32(i);

    memcpy(array, &be_i, sizeof(be_i));
}

uint32_t arrayToEhIndex(const uint8_t *array)
{
    return be32toh(*(uint32_t *)array);
}

static void generateHash(blake2b_state *S, const uint32_t g, uint8_t *hash, const size_t hashLen)
{
    const uint32_t le_g = htole32(g);
    blake2b_state digest = *S; /* copy */

    blake2b_update(&digest, (uint8_t *)&le_g, sizeof(le_g));
    blake2b_final(&digest, hash, hashLen);
}

/* https://github.com/zcash/zcash/issues/1175 */
// (tmpHash + i*25, 25,hash, 30,20, 0)
//512, 1344, xxx, 2048, 21, 1
static void expandArray(const unsigned char *in, const size_t in_len,
                        unsigned char *out, const size_t out_len,
                        const size_t bit_len, const size_t byte_pad)
{
    assert(bit_len >= 8);
    assert(8 * sizeof(uint32_t) >= 7 + bit_len);		

    const size_t out_width = (bit_len + 7) / 8 + byte_pad;	//out_width=4
    assert(out_len == 8 * out_width * in_len / bit_len);

    const uint32_t bit_len_mask = ((uint32_t)1 << bit_len) - 1;		//0xfffff

    // The acc_bits least-significant bits of acc_value represent a bit sequence
    // in big-endian order.
    size_t acc_bits = 0;
    uint32_t acc_value = 0;

    size_t j = 0;
    for (size_t i = 0; i < in_len; i++)
    {
        acc_value = (acc_value << 8) | in[i];
        acc_bits += 8;

        // When we have bit_len or more bits in the accumulator, write the next
        // output element.
        if (acc_bits >= bit_len) //acc_bits >= 20
        {
            acc_bits -= bit_len;
            for (size_t x = 0; x < byte_pad; x++)
            {
                out[j + x] = 0;
            }
            for (size_t x = byte_pad; x < out_width; x++)
            {
                out[j + x] = (
                                 // Big-endian
                                 acc_value >> (acc_bits + (8 * (out_width - x - 1)))
                             ) & (
                                 // Apply bit_len_mask across byte boundaries
                                 (bit_len_mask >> (8 * (out_width - x - 1))) & 0xFF
                             );
            }
            j += out_width;
        }
    }
}

// 每个index是4个字节32bits，有用的是它的地位21bits，这个函数将32bits中的21bits提取出来，
//逐个衔接，此处in_len是2048个字节，共有2048*8bits，每32bits取21bits，所以还剩下
//2048*8 * （21/32）/ 8 字节 即64*21个字节，等于out_len
static void compressArray(const unsigned char *in, const size_t in_len,
                          unsigned char *out, const size_t out_len,
                          const size_t bit_len, const size_t byte_pad)
{
    assert(bit_len >= 8);
    assert(8 * sizeof(uint32_t) >= 7 + bit_len);

    const size_t in_width = (bit_len + 7) / 8 + byte_pad;		//4
    assert(out_len == bit_len * in_len / (8 * in_width));

    const uint32_t bit_len_mask = ((uint32_t)1 << bit_len) - 1;		//2^21-1

    // The acc_bits least-significant bits of acc_value represent a bit sequence
    // in big-endian order.
    size_t acc_bits = 0;
    uint32_t acc_value = 0;

    size_t j = 0;

    for (size_t i = 0; i < out_len; i++)
    {
        // When we have fewer than 8 bits left in the accumulator, read the next
        // input element. 
        if (acc_bits < 8)
        {
            acc_value = acc_value << bit_len;
            for (size_t x = byte_pad; x < in_width; x++)
            {
            								// Apply bit_len_mask across byte boundaries
                acc_value = acc_value | (( in[j + x] & ((bit_len_mask >> (8 * (in_width - x - 1))) & 0xFF)) << (8 * (in_width - x - 1))); // Big-endian
			}
            j += in_width;
            acc_bits += bit_len;
        }

        acc_bits -= 8;
		out[i] = (acc_value >> acc_bits) & 0xFF;
		
    }
}

static int compareSR(const void *p1, const void *p2, void *arg)
{
    return memcmp(p1, p2, *(int *)arg) < 0;
}

//如果a和b中有index相同的，则返回0，不做异或操作？？？？
//此处的就是为了排除一条记录中有index相同的
static int distinctSortedArrays(const uint32_t *a, const uint32_t *b, const size_t len)
{

    int i = len - 1, j = len - 1;
    uint32_t prev;
	
    prev = (a[i] >= b[j])? a[i--] : b[j--];
    while (j >= 0 && i >= 0)
    {
        uint32_t acc = (a[i] >= b[j])? a[i--] : b[j--];
        if (acc == prev) {
			return 0;
		}
        prev = acc;
    }

    return 1;
}

// Checks if the intersection of a.indices and b.indices is empty
// 比较两个数的index大小，小的放在前面，大的放在后面
static int distinctIndices(const uint8_t *a, const uint8_t *b, const size_t len, const size_t lenIndices)
{	
    return distinctSortedArrays((uint32_t *)(a + len), (uint32_t *)(b + len), lenIndices / sizeof(uint32_t));
}

static int hasCollision(const uint8_t *a, const uint8_t *b, const size_t len)
{
    return memcmp(a, b, len) == 0;
}

//Xc, 6, 2048, 20, soln, 64*21
static int getIndices(const uint8_t *hash, size_t len, size_t lenIndices, size_t cBitLen,
                      uint8_t *data, size_t maxLen)
{
    assert(((cBitLen + 1) + 7) / 8 <= sizeof(uint32_t));
    size_t minLen = (cBitLen + 1) * lenIndices / (8 * sizeof(uint32_t));	//21*2048/32 = 21*64
    size_t bytePad = sizeof(uint32_t) - ((cBitLen + 1 ) + 7 ) / 8;			//4-3=1
    if (minLen > maxLen)
        return -1;
    if (data)	//hash+6, 2048, data, 21*64, 21, 1
        compressArray(hash + len, lenIndices, data, minLen, cBitLen + 1, bytePad);
    return minLen;
}

//此处对a和b两组数据的所有index进行从大到小排序，比如依次写到dst[3], dst[2],dst[1], dst[0]
//所以事实上是从小到大排序的
static void joinSortedArrays(uint32_t *dst, const uint32_t *a, const uint32_t *b, const size_t len)
{
    int i = len - 1, j = len - 1, k = len * 2;

	while (k > 0) 
	{
		dst[--k] = (j < 0 || (i >= 0 && a[i] >= b[j]))? a[i--] : b[j--];
	}
}

static void combineRows(uint8_t *hash, const uint8_t *a, const uint8_t *b,
                        const size_t len, const size_t lenIndices, const int trim)
{
	//从第3个字节开始做异或，因为前三个字节是相等的，异或肯定为0, 所以异或后少了最终数据少了3个字节
	//最后的4个标识索引的字节暂不做处理
    for (int i = trim; i < len; i++)
	{
        hash[i - trim] = a[i] ^ b[i];
	}

    joinSortedArrays((uint32_t *)(hash + len - trim),
                     (uint32_t *)(a + len), (uint32_t *)(b + len),
                     lenIndices / sizeof(uint32_t));
}

static int isZero(const uint8_t *hash, size_t len)
{
    // This doesn't need to be constant time.
    for (int i = 0; i < len; i++)
    {
        if (hash[i] != 0)
            return 0;
    }
    return 1;
}

void __bin2hex(char *s, const unsigned char *p, size_t len)
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
char *bin2hex(const unsigned char *p, size_t len)
{
    ssize_t slen;
    char *s;

    slen = len * 2 + 1;
    if (slen % 4)
        slen += 4 - (slen % 4);
    s = calloc(slen, 1);

    __bin2hex(s, p, len);

    return s;
}

static const int hex2bin_tbl[256] =
{
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

/* Does the reverse of bin2hex but does not allocate any ram */
bool hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
    int nibble1, nibble2;
    unsigned char idx;
    bool ret = false;

    while (*hexstr && len)
    {


        idx = *hexstr++;
        nibble1 = hex2bin_tbl[idx];
        idx = *hexstr++;
        nibble2 = hex2bin_tbl[idx];

        *p++ = (((unsigned char)nibble1) << 4) | ((unsigned char)nibble2);
        --len;
    }

    if (len == 0 && *hexstr == 0)
        ret = true;
    return ret;
}

static int basicSolve(blake2b_state *digest,
                      const int n, const int k,
                      bool (*validBlock)(void*, const unsigned char*),
                      void* validBlockData)
{
    const int collisionBitLength  = n / (k + 1);
    const int collisionByteLength = (collisionBitLength + 7) / 8;
    const int hashLength = (k + 1) * collisionByteLength;
    const int indicesPerHashOutput = 512 / n;
    const int hashOutput = indicesPerHashOutput * n / 8;
    const int fullWidth  = 2 * collisionByteLength + sizeof(uint32_t) * (1 << (k - 1));
    const int initSize   = 1 << (collisionBitLength + 1);
    const int equihashSolutionSize = (1 << k) * (n / (k + 1) + 1) / 8;

    // In comments values for n=200, k=9
    D(": n %d, k %d\n",              n, k);                 //  200, 9
    D(": collisionBitLength %d\n",   collisionBitLength);   //   20
    D(": collisionByteLength %d\n",  collisionByteLength);  //    3
    D(": hashLength %d\n",           hashLength);           //   30
    D(": indicesPerHashOutput %d\n", indicesPerHashOutput); //    2
    D(": hashOutput %d\n",           hashOutput);           //   50
    D(": fullWidth %d\n",            fullWidth);            // 1030
    D(": initSize %d (memory %u)\n",
      initSize, initSize * fullWidth); // 2097152, 2160066560

    uint8_t hash[fullWidth];
    size_t x_room  = initSize * sizeof(hash);
    size_t xc_room = initSize * sizeof(hash);
    uint8_t *x  = malloc(x_room);
    uint8_t *xc = malloc(xc_room); // merge array
    assert(x);
    assert(xc);

#if (BUCKET_SORT==1)
	bucket_sort_init();
#endif
#define X(y)  (x  + (hashLen                       + lenIndices)     * (y))
#define Xc(y) (xc + (hashLen - collisionByteLength + lenIndices * 2) * (y))

    uint8_t tmpHash[hashOutput];
    uint32_t x_size = 0, xc_size = 0;
    size_t hashLen    = hashLength;       /* Offset of indices array;
                         shortens linearly by collisionByteLength. */
    size_t lenIndices = sizeof(uint32_t); /* Byte length of indices array;
                         doubles with every round. */
    D("Generating first list\n");

	char *hex_buff = NULL;
	//产生initSize个数，这是将输入(Block Header)生成广义生日问题的第一步
    for (uint32_t g = 0; x_size < initSize; g++)
    {
        generateHash(digest, g, tmpHash, hashOutput);

#if (BUCKET_SORT==1)
		bucket_sort_output_file_1(tmpHash, hashOutput, g);
		bucket_sort_pack_hash_to_buckets2(tmpHash, hashOutput, g);
#endif
        for (uint32_t i = 0; i < indicesPerHashOutput && x_size < initSize; i++)
        {
        	//每20个bit前面补4个0，从200个bits扩展到240个bits，共30个字节
			expandArray(tmpHash + (i * n / 8), n / 8,
                        hash, hashLength,
                        collisionBitLength, 0); //(tmpHash + i*25, 25,hash, 30,20, 0)

			//每个30个字节的hash数后面加4个字节，表示该hash值的序号
            ehIndexToArray(g * indicesPerHashOutput + i, hash + hashLength); //(g*2+i, hash+hashLength)

			//每得到一个34字节的值，将它添加到申请的堆x末尾。
            memcpy(X(x_size), hash, hashLen + lenIndices);	//34Bytes

			hex_buff = bin2hex(X(x_size),hashLen + lenIndices);
			free(hex_buff);
            ++x_size;
        }
    }

#if (BUCKET_SORT==1)
	bucket_sort_output_file_2();
	bucket_sort_exit();
#endif

	//轮循8轮，每次对比前24bits，两两对比如果这24bit相等，则进行异或合并，生成一个新的数，并记录这两个数的index
	//所有的新数放到第二次轮询中，第二轮产生的新数放到第三轮中，依此操作到第八轮
	//8轮完成后，剩下6字节未合并，剩下6字节在这个for循环中不处理，再后面一次性处理合并6个字节，
	//最后数据被逐渐合并，剩下的都是index数据
    for (int r = 1; r < k && x_size > 0; r++)
    {
        D("Round %d:\n", r);
        D("- Sorting list (size %d, %ld)\n", x_size, x_size * (hashLen + lenIndices));

		//对x中的数，以34字节为单位，从大到小排序
        qsort_r(x, x_size, hashLen + lenIndices, compareSR, (int *)&collisionByteLength);
#if 0
		if (r == 8) {
			FILE *fp1 = NULL;
			char filename[32] = {0};
			sprintf(filename, "rount%d.txt", r);
			fp1 = fopen(filename, "w+");
			if (fp1 == NULL) {
				perror("open error\n");
				exit(1);
			}
			for (int q=0; q<x_size; q++)
			{
				hex_buff = bin2hex(X(q), hashLen+lenIndices);
				fprintf(fp1, "%s\n", hex_buff);
				free(hex_buff);
			}
			fclose(fp1);
			exit(1);
		}
#endif
        D("- Finding collisions\n");
        for (int i = 0; i < x_size - 1; )
        {
            // 2b) Find next set of unordered pairs with collisions on the next n/(k+1) bits
            int j = 1;

			//从x中拿两组数，对比头3个字节，如果相等继续循环，直到找到不相等的，跳出while
			//跳出while后就要合并刚刚发现的这些相等数据了
            while (i + j < x_size && hasCollision(X(i), X(i + j), collisionByteLength))
            {
                j++;
            }

            /* Found partially collided values range between i and i+j. */

            // 2c) Calculate tuples (X_i ^ X_j, (i, j))

            for (int l = 0; l < j - 1; l++)
            {
                for (int m = l + 1; m < j; m++)
                {
                	//这个函数处理的两组数据的index部分，
                    if (distinctIndices(X(i + l), X(i + m), hashLen, lenIndices))
                    {
                    	//r=1 hashlen=30, lenindices=4
                    	//r=2 hashlen=27, lenindices=8
                    	//r=3 hashlen=24, lenindices=16
                    	//r=4 hashlen=21, lenindices=32
                    	//r=5 hashlen=18, lenindices=64
                    	//r=6 hashlen=15, lenindices=128
                    	//r=7 hashlen=12, lenindices=256
                    	//r=8 hashlen=9,  lenindices=512
                    	//这个函数执行异或操作，并合并出新的数据，包含数据+index小+index大
                        combineRows(Xc(xc_size), X(i + l), X(i + m), hashLen, lenIndices, collisionByteLength);		
                        ++xc_size;
                        if (Xc(xc_size) >= (xc + xc_room))
                        {
                            D("! realloc\n");
                            xc_room += 100000000;
                            xc = realloc(xc, xc_room);
                            assert(xc);
                        }
                    }
                }
            }

            /* Skip processed block to the next. */
            i += j;
//			getchar();
        }

        hashLen -= collisionByteLength;
        lenIndices *= 2;

        /* swap arrays */
        swap(x, xc);
        swap(x_room, xc_room);
        x_size = xc_size;
        xc_size = 0;
    } /* step 2 */

    // k+1) Find a collision on last 2n(k+1) bits
    
    //x的结构为:x_size * (6Bytes data + 512Bytes index + 512Bytes index) = 1030Bytes

	D("Final round:\n");
    int solnr = 0;
    if (x_size > 1)
    {
        D("- Sorting list (size %d, %ld) hashLen=%u lenIndices=%u\n", x_size, x_size * (hashLen + lenIndices), (uint32_t)hashLen, (uint32_t)lenIndices);
        qsort_r(x, x_size, (hashLen + lenIndices), compareSR, (int *)&hashLen);

        D("- Finding collisions\n");
        for (int i = 0; i < x_size - 1; )
        {
            int j = 1;
            while (i + j < x_size && hasCollision(X(i), X(i + j), hashLen))
            {
                j++;
            }

            for (int l = 0; l < j - 1; l++)
            {
                for (int m = l + 1; m < j; m++)
                {
                    combineRows(Xc(xc_size), X(i + l), X(i + m), hashLen, lenIndices, 0);
                    if (isZero(Xc(xc_size), hashLen) &&
                        distinctIndices(X(i + l), X(i + m), hashLen, lenIndices))
                    {
                        uint8_t soln[equihashSolutionSize];
						//此处的soln就是有效的index集合
                        int ssize = getIndices(Xc(xc_size), hashLen, 2 * lenIndices, collisionBitLength,
                                               soln, sizeof(soln));
                        ++solnr;
                        D("+ collision of size %d (%d)\n", equihashSolutionSize, ssize);
                        assert(equihashSolutionSize == ssize);
#if 1
                        for (int y = 0; y < 2 * lenIndices; y += sizeof(uint32_t))
                            D(" %u", arrayToEhIndex(Xc(xc_size) + hashLen + y));
                        D("\n");
#endif
                        dump_hex(soln, equihashSolutionSize);
                        printf("\n");
                        if (validBlock)
                        {
                            if (validBlock(validBlockData, soln))
                            {
                                D("+ valid\n");
                            }
                            else
                            {
                                D("+ NOT VALID\n");
                            }
                        }
                    }
                    ++xc_size;
                    assert(xc_size < xc_room);
                }
            }
            i += j;
        }
        D("- Found %d solutions.\n", solnr);
    }
    else
        D("- List is empty\n");

    free(x);
    free(xc);
    return solnr;
}

struct validData
{
    int n;
    int k;
    blake2b_state *digest;
};

//根据soln中的index，重新扔到generatehash函数中产生对应的512个数据，
//并将这些数据逐个异或，如果最终结果为0，则验证通过。
bool basicValidator(void *data, const unsigned char *soln)
{
    const struct validData *v = data;
    const int n = v->n;
    const int k = v->k;
    blake2b_state *digest = v->digest;
    const int collisionBitLength  = n / (k + 1);					//20
    const int collisionByteLength = (collisionBitLength + 7) / 8;	//3
    const int hashLength = (k + 1) * collisionByteLength;			//30
    const int indicesPerHashOutput = 512 / n;						//2
    const int hashOutput = indicesPerHashOutput * n / 8;			//50
    const int equihashSolutionSize = (1 << k) * (n / (k + 1) + 1) / 8;	//1344
    const int solnr = 1 << k;										//2^9
    uint32_t indices[solnr];

#if 0
	char *read_index = NULL;
	size_t read_index_len = 0;

	uint8_t bin0[1344] = {0};
	FILE *fp = NULL;
	fp = fopen("soln.txt", "r+");
	if (fp == NULL){
		perror("open error\n");
		exit(1);
	}
	getline(&read_index, &read_index_len, fp);
	hex2bin(bin0, read_index, 1344);
#endif
	//此处重新将21bits的index，前面补0，变成32bits
    expandArray(soln, equihashSolutionSize, (unsigned char *)&indices, sizeof(indices), collisionBitLength + 1, 1);

	D("Validate:");
    uint8_t vHash[hashLength];
    memset(vHash, 0, sizeof(vHash));
    for (int j = 0; j < solnr; j++)
    {
        uint8_t tmpHash[hashOutput];
        uint8_t hash[hashLength];
        int i = be32toh(indices[j]);
        D(" %d", i);
        generateHash(digest, i / indicesPerHashOutput, tmpHash, hashOutput);
        expandArray(tmpHash + (i % indicesPerHashOutput * n / 8), n / 8, hash, hashLength, collisionBitLength, 0);
        for (int k = 0; k < hashLength; ++k)
            vHash[k] ^= hash[k];
    }
    D("\n");
    return isZero(vHash, sizeof(vHash));
}

// API wrapper
int SolverFunction(const unsigned char* input,
                   bool (*validBlock)(void*, const unsigned char*),
                   void* validBlockData,
                   bool (*cancelled)(void*),
                   void* cancelledData,
                   int numThreads,
                   int n, int k)
{
    blake2b_state digest[1];
    struct validData valData = { .n = n, .k = k, .digest = digest };
    digestInit(digest, n, k);
    blake2b_update(digest, input, 140);
    if (!validBlock)
    {
        validBlock     = basicValidator;
        validBlockData = &valData;
    }
    return basicSolve(digest, n, k, validBlock, validBlockData);
}

static void hashNonce(blake2b_state *S, uint32_t nonce)
{
    for (int i = 0; i < 8; i++)
    {
        uint32_t le = i == 0? htole32(nonce) : 0;
        blake2b_update(S, (uint8_t *)&le, sizeof(le));
    }
}

int main(int argc, char **argv)
{
    int       n = 200;
    int       k = 9;
    char    *ii = "block header";
    uint32_t nn = 0;
    int threads = 1;
    char *input = NULL;
    int  tFlags = 0;
    int opt;

    while ((opt = getopt(argc, argv, "qn:k:N:I:t:i:h")) != -1)
    {
        switch (opt)
        {
            case 'q':
                debug = 0;
                break;
            case 'n':
                n = atoi(optarg);
                break;
            case 'k':
                k = atoi(optarg);
                break;
            case 'N':
                nn = strtoul(optarg, NULL, 0);
                tFlags = 1;
                break;
            case 'I':
                ii = strdup(optarg);
                tFlags = 2;
                break;
            case 't':
                threads = atoi(optarg); /* ignored */
                break;
            case 'i':
                input = strdup(optarg);
                break;
            case 'h':
            default:
                fprintf(stderr, "Solver CPI API mode:\n");
                fprintf(stderr, "  %s -i input -n N -k K\n", argv[0]);
                fprintf(stderr, "Test vector mode:\n");
                fprintf(stderr, "  %s [-n N] [-k K] [-I string] [-N nonce]\n", argv[0]);
                exit(1);
        }
    }
    if (tFlags && input)
    {
        fprintf(stderr, "Test vector parameters (-I, -N) cannot be used together with input (-i)\n");
        exit(1);
    }

    if (input)
    {
        uint8_t block_header[140];
        int fd = open(input, O_RDONLY);
        if (fd == -1)
        {
            fprintf(stderr, "open: %s: %s\n", input, strerror(errno));
            exit(1);
        }
        int i = read(fd, block_header, sizeof(block_header));
        if (i == -1)
        {
            fprintf(stderr, "read: %s: %s\n", input, strerror(errno));
            exit(1);
        }
        else if (i != sizeof(block_header))
        {
            fprintf(stderr, "read: %s: Zcash block header is not full\n", input);
            exit(1);
        }
        close(fd);

        int ret = SolverFunction(block_header, NULL, NULL, NULL, NULL, threads, n, k);
        exit(ret < 0);
    }
    else
    {
        blake2b_state digest;
		struct validData valData = { .n = n, .k = k, .digest = &digest };

		uint8_t ii_bin[140] = {0};
        digestInit(&digest, n, k);

		D("%s\n",ii);

		hex2bin(ii_bin,ii,140);
        blake2b_update(&digest, ii_bin, 140);
		//D("%d\n",nn);
        //hashNonce(digest, nn);

        basicSolve(&digest, n, k, basicValidator, &valData);
    }
}
