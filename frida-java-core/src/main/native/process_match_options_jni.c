#include "frida_common.h"

// ProcessMatchOptions JNI implementations

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_ProcessMatchOptions_setTimeout(JNIEnv *env, jobject obj, jint timeout) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaProcessMatchOptions *opts = (FridaProcessMatchOptions *) native_ptr;
  g_object_set(opts, "timeout", (gint)timeout, NULL);
}

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_ProcessMatchOptions_getTimeout(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaProcessMatchOptions *opts = (FridaProcessMatchOptions *) native_ptr;
  gint timeout = 0;
  g_object_get(opts, "timeout", &timeout, NULL);
  return (jint)timeout;
}
