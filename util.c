#include <stdio.h>
#include <stdlib.h>

void _assert(int cond, const char* msg, const char* file, unsigned int line)
{
    if (cond == 0)
    {
        fprintf(stderr, "Assertion failed! File %s, Line: %i, Message: %s\n", file, line, msg);
        exit(-1);
    }
}

#define assert(cond, msg) _assert(cond, msg, __FILE__, __LINE__)

int mini(int a, int b)
{
    if (a < b)
        return a;
    else
        return b;
}
