#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    while(1)
    {
        printf("Waiting...\n");
        sleep(1);
    }
    return 0;
}