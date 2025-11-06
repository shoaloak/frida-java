#include "frida_common.h"

// Spawn JNI implementations

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_Spawn_getPid(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaSpawn *spawn = (FridaSpawn *) native_ptr;
  return (jint) frida_spawn_get_pid(spawn);
}

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_SpawnList_size(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaSpawnList *list = (FridaSpawnList *) native_ptr;
  return (jint) frida_spawn_list_size(list);
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_SpawnList_get(JNIEnv *env, jobject obj, jint index) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaSpawnList *list = (FridaSpawnList *) native_ptr;
  FridaSpawn *spawn = frida_spawn_list_get(list, index);
  g_object_ref(spawn);
  jclass spawn_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/Spawn");
  jmethodID spawn_ctor = (*env)->GetMethodID(env, spawn_class, "<init>", "(J)V");
  return (*env)->NewObject(env, spawn_class, spawn_ctor, (jlong) spawn);
}

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_Spawn_getIdentifier(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaSpawn *spawn = (FridaSpawn *) native_ptr;
  const gchar *id = frida_spawn_get_identifier(spawn);
  return (*env)->NewStringUTF(env, id);
}
