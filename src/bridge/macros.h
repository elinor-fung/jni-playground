#pragma once

#ifdef TARGET_UNIX
    #define PALEXPORT __attribute__ ((__visibility__ ("default")))
#else
    #define PALEXPORT __declspec(dllexport)
#endif
