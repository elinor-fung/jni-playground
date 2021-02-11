#include <jni.h>
#include "pal_jni.h"
#include "bridge.h"
#include "macros.h"

JavaVM *g_vm = NULL;

PALEXPORT bool create_jvm()
{
    JavaVMInitArgs vm_args = { 0 };
    vm_args.options = NULL;
    vm_args.nOptions = 0;
    vm_args.version  = JNI_VERSION_1_8;
    vm_args.ignoreUnrecognized = false;

    JNIEnv *env = NULL;
    jint res = JNI_CreateJavaVM(&g_vm, (void **)&env, &vm_args);
    if (res != JNI_OK) {
        LOG_ERROR("Failed to create Java VM: %d", res);
        return false;
    }

    JNI_OnLoad(g_vm, NULL);
    return true;
}

PALEXPORT void print_version()
{
    JNIEnv* env = GetJNIEnv();
    jclass systemClass = GetClassGRef(env, "java/lang/System");
    jmethodID systemGetProperty = GetMethod(env, true, systemClass, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;");

    jobject prop = JSTRING("java.version");
    jstring ver =  (jstring)(*env)->CallStaticObjectMethod(env, systemClass, systemGetProperty, prop);

    const char* verStr = (*env)->GetStringUTFChars(env, ver, NULL);
    printf("java.version : %s\n", verStr);
    (*env)->ReleaseStringUTFChars(env, ver, verStr);
}

PALEXPORT void destroy_jvm()
{
    (*g_vm)->DestroyJavaVM(g_vm);
}
