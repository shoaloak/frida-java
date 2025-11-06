#include "frida_common.h"

// Helper function to throw RuntimeException
void throw_runtime_exception(JNIEnv *env, const char *message) {
  jclass exception_class = (*env)->FindClass(env, "java/lang/RuntimeException");
  (*env)->ThrowNew(env, exception_class, message);
}
