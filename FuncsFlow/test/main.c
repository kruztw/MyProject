#include <stdio.h>
#include "include/h1.h"

void sayhi(const char *name)
{
    printf("hello %s\n", name);
}

int main()
{
    char name[100];
    puts("what's your name ?");
    scanf("%99s", name);
    sayhi(name);

    /* just for demo */
    for (int i = 0; i < 2; i++)
        func1();

    return 0;
}
