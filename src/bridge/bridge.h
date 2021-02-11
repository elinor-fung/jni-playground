#pragma once

#include <jni.h>
#include <stdbool.h>

#include "macros.h"

PALEXPORT bool create_jvm();
PALEXPORT void destroy_jvm();
PALEXPORT void print_version();
PALEXPORT jstring get_version(JNIEnv **env);