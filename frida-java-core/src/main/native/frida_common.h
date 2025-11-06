#ifndef FRIDA_COMMON_H
#define FRIDA_COMMON_H

#include <jni.h>
#include <frida-core.h>
#include <string.h>

// Helper function to throw RuntimeException
void throw_runtime_exception(JNIEnv *env, const char *message);

// Helper function to convert Device.Type enum
jint device_type_to_java(FridaDeviceType type);

#endif // FRIDA_COMMON_H
