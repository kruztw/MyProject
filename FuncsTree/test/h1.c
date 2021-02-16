#include <stdio.h>
#include "include/h1.h"

int func1() {
    printf("h1.c: you call func1\n");
    func2();
    return 0;
}

void func2()
{
    printf("h1.c you call func2\n");
}
