#include "frida_common.h"

// Process JNI implementations

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_Process_getPid(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jfieldID native_ptr_field = (*env)->GetFieldID(env, cls, "nativePtr", "J");
  jlong native_ptr = (*env)->GetLongField(env, obj, native_ptr_field);
  if (native_ptr == 0) return 0;
  FridaProcess *proc = (FridaProcess *) native_ptr;
  return (jint) frida_process_get_pid(proc);
}

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_Process_getName(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jfieldID native_ptr_field = (*env)->GetFieldID(env, cls, "nativePtr", "J");
  jlong native_ptr = (*env)->GetLongField(env, obj, native_ptr_field);
  if (native_ptr == 0) return NULL;
  FridaProcess *proc = (FridaProcess *) native_ptr;
  const gchar *name = frida_process_get_name(proc);
  return (*env)->NewStringUTF(env, name);
}

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_Process_getParentPid(JNIEnv *env, jobject obj) {
  // frida_process_get_parent_pid is not available in this Frida SDK version.
  return 0;
}

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_Process_getIdentifier(JNIEnv *env, jobject obj) {
  // frida_process_get_identifier is not available in this Frida SDK version.
  return NULL;
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Process_disposeNative(JNIEnv *env, jobject obj, jlong native_ptr) {
  if (native_ptr != 0) {
    g_object_unref((FridaProcess *) native_ptr);
  }
}
