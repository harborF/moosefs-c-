#include "ChunkFileCache.h"
#include <stdio.h>

int main(){

    printf("begin.......\n");

    file_cache_init();

    const char* szBuf = "adsflksakkcxjcheoijlksjdjowjoeijwlefokjhfdsljkluuokljls";

    for (int i = 0; i < 2000; ++i)
    {
        file_cache_insert(100 + i, (uint8_t*)szBuf, strlen(szBuf));
    }

    for (int j = 1100; j < 2000;++j)
    {
        uint8_t szRBuf[1024] = {0};
        if (file_cache_search(j, 0, strlen(szBuf), szRBuf))
        {
            printf("%s\n", (char*)szRBuf);
        }
    }
    file_cache_term();
    printf("end.......\n");

    return 0;
}
