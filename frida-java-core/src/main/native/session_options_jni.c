#include "frida_common.h"

// SessionOptions JNI implementations

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_SessionOptions_setPersistTimeout(JNIEnv *env, jobject obj, jint timeout) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaSessionOptions *opts = (FridaSessionOptions *) native_ptr;
  g_object_set(opts, "persist-timeout", (gint)timeout, NULL);
}

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_SessionOptions_getPersistTimeout(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaSessionOptions *opts = (FridaSessionOptions *) native_ptr;
  gint timeout = 0;
  g_object_get(opts, "persist-timeout", &timeout, NULL);
  return (jint)timeout;
}
