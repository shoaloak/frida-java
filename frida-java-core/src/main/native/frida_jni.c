#include "frida_common.h"
#include <pthread.h>

// Global variables for reference counting
static int frida_ref_count = 0;
static pthread_mutex_t frida_ref_mutex = PTHREAD_MUTEX_INITIALIZER;

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_Frida_getVersionString(JNIEnv *env, jclass cls) {
  const gchar *version = frida_version_string();
  return (*env)->NewStringUTF(env, version);
}

JNIEXPORT jintArray JNICALL Java_nl_axelkoolhaas_frida_1java_Frida_getVersion(JNIEnv *env, jclass cls) {
  guint major, minor, micro, nano;
  frida_version(&major, &minor, &micro, &nano);
  jintArray result = (*env)->NewIntArray(env, 4);
  if (result == NULL) {
    return NULL; // out of memory error thrown
  }
  jint fill[4];
  fill[0] = (jint) major;
  fill[1] = (jint) minor;
  fill[2] = (jint) micro;
  fill[3] = (jint) nano;
  (*env)->SetIntArrayRegion(env, result, 0, 4, fill);
  return result;
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Frida_init(JNIEnv *env, jclass cls) {
  pthread_mutex_lock(&frida_ref_mutex);
  if (frida_ref_count == 0) {
    frida_init();
  }
  frida_ref_count++;
  pthread_mutex_unlock(&frida_ref_mutex);
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Frida_deinit(JNIEnv *env, jclass cls) {
  pthread_mutex_lock(&frida_ref_mutex);
  if (frida_ref_count > 0) {
    frida_ref_count--;
    // Don't call frida_deinit() during normal execution to avoid crashes
    // when multiple test classes or components try to deinitialize Frida.
    // The Frida library will clean up automatically when the JVM shuts down.
  }
  pthread_mutex_unlock(&frida_ref_mutex);
}
