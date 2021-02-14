#include "bridge.h"

#include "x509_test.h"

int main(int argc, char **argv)
{
    if (!create_jvm())
       return 1;

    print_version();
    printf("\n");

    x509_test();

    destroy_jvm();
    return 0;
}