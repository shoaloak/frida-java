#include "frida_common.h"

// Helper function to throw RuntimeException
void throw_runtime_exception(JNIEnv *env, const char *message) {
  jclass exception_class = (*env)->FindClass(env, "java/lang/RuntimeException");
  (*env)->ThrowNew(env, exception_class, message);
}

// Helper function to convert Device.Type enum (not used in current implementation)
jint device_type_to_java(FridaDeviceType type) {
  switch (type) {
    case FRIDA_DEVICE_TYPE_LOCAL: return 0; // LOCAL
    case FRIDA_DEVICE_TYPE_REMOTE: return 1; // REMOTE
    case FRIDA_DEVICE_TYPE_USB: return 2; // USB
    default: return 0;
  }
}
