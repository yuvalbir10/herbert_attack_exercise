//
//
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <x86intrin.h>
#include <inttypes.h>

#define ARRAY_SIZE (32768)
char Array1[ARRAY_SIZE];
char Array3[ARRAY_SIZE];

u_int64_t my_loop(char* arr1, char* arr2, char* out)
{
        unsigned int _junk;
        u_int64_t start = _rdtscp(&_junk);
        register int res2, res3;
        for (register int i = 0; i < ARRAY_SIZE; i++) {
                arr1[i] = 1;
                res2 = arr2[i];
                res3 += res2;
                //arr1[res2] = res2 ;


        }
        u_int64_t stop = _rdtscp(&_junk);
        *out += res3;
        return stop - start;

}

int main(int argc, char* argv[]) {
    u_int64_t time;
    for (int i = 0 ; i<ARRAY_SIZE;i++)
    {
            Array3[i] = i & 255;
            Array1[i] = i & 255;
    }
    int offset = atoi(argv[1]);
    char y = 'a';

    time = my_loop(Array1,Array3+offset, &y);
    if ( offset == 0)
    {
        printf("RunTime With alias : %lu\n", time);
    }
    else{
        printf("RunTime Without alias : %lu\n", time);
    }
}