#include "frida_common.h"

// FrontmostQueryOptions JNI implementations

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_FrontmostQueryOptions_setUser(JNIEnv *env, jobject obj, jstring user) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaFrontmostQueryOptions *opts = (FridaFrontmostQueryOptions *) native_ptr;
  const char *cuser = (*env)->GetStringUTFChars(env, user, 0);
  g_object_set(opts, "user", cuser, NULL);
  (*env)->ReleaseStringUTFChars(env, user, cuser);
}

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_FrontmostQueryOptions_getUser(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaFrontmostQueryOptions *opts = (FridaFrontmostQueryOptions *) native_ptr;
  gchar *user = NULL;
  g_object_get(opts, "user", &user, NULL);
  jstring result = user ? (*env)->NewStringUTF(env, user) : NULL;
  g_free(user);
  return result;
}
