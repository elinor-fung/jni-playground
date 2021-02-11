#include <jni.h>
#include <pal_jni.h>

void print_version()
{
    JNIEnv* env = GetJNIEnv();
    jclass systemClass = GetClassGRef(env, "java/lang/System");
    jmethodID systemGetProperty = GetMethod(env, true, systemClass, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;");

    jobject prop = JSTRING("java.version");
    jstring ver =  (jstring)(*env)->CallStaticObjectMethod(env, systemClass, systemGetProperty, prop);
    const char* verStr = (*env)->GetStringUTFChars(env, ver, NULL);
    printf("java.version : %s", verStr);
    (*env)->ReleaseStringUTFChars(env, ver, verStr);
}

int main(int argc, char **argv)
{
    JavaVMInitArgs  vm_args;
    vm_args.nOptions = 0;
    vm_args.version  = JNI_VERSION_1_8;

    JavaVM *vm;
    JNIEnv *env;
    jint res = JNI_CreateJavaVM(&vm, (void **)&env, &vm_args);
    if (res != JNI_OK) {
        printf("Failed to create Java VM: %d", res);
        return 1;
    }

    JNI_OnLoad(vm, NULL);

    print_version();
    
    (*vm)->DestroyJavaVM(vm);
    return 0;
}