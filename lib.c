#include <stdio.h>
#include <stdlib.h>

void __attribute__((constructor)) lib_entry()
{
    //It prints "Injected!" once the library gets loaded.
    printf("Injected!\n");
}