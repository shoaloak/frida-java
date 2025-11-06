#include "frida_common.h"

// ProcessQueryOptions JNI implementations

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_ProcessQueryOptions_setName(JNIEnv *env, jobject obj, jstring name) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaProcessQueryOptions *opts = (FridaProcessQueryOptions *) native_ptr;
  const char *cname = (*env)->GetStringUTFChars(env, name, 0);
  g_object_set(opts, "name", cname, NULL);
  (*env)->ReleaseStringUTFChars(env, name, cname);
}

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_ProcessQueryOptions_getName(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaProcessQueryOptions *opts = (FridaProcessQueryOptions *) native_ptr;
  gchar *name = NULL;
  g_object_get(opts, "name", &name, NULL);
  jstring result = name ? (*env)->NewStringUTF(env, name) : NULL;
  g_free(name);
  return result;
}
