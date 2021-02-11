#include "bridge.h"

int main(int argc, char **argv)
{
    if (!create_jvm())
       return 1;

    print_version();

    destroy_jvm();
    return 0;
}