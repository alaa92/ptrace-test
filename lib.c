#include <stdio.h>
#include <stdlib.h>

void __attribute__((constructor)) lib_entry()
{
    printf("Injected!\n");
}