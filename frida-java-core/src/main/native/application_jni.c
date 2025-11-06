#include "frida_common.h"

// Application JNI implementations

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_Application_getIdentifier(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaApplication *app = (FridaApplication *) native_ptr;
  const gchar *id = frida_application_get_identifier(app);
  return (*env)->NewStringUTF(env, id);
}

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_Application_getName(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaApplication *app = (FridaApplication *) native_ptr;
  const gchar *name = frida_application_get_name(app);
  return (*env)->NewStringUTF(env, name);
}

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_Application_getPid(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaApplication *app = (FridaApplication *) native_ptr;
  return (jint) frida_application_get_pid(app);
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_Application_getParameters(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaApplication *app = (FridaApplication *) native_ptr;
  GHashTable *params = frida_application_get_parameters(app);
  if (!params) return NULL;
  jclass map_class = (*env)->FindClass(env, "java/util/HashMap");
  jmethodID map_ctor = (*env)->GetMethodID(env, map_class, "<init>", "()V");
  jobject map = (*env)->NewObject(env, map_class, map_ctor);
  jmethodID put_method = (*env)->GetMethodID(env, map_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
  GHashTableIter iter;
  gpointer key, value;
  g_hash_table_iter_init(&iter, params);
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    jstring jkey = (*env)->NewStringUTF(env, (const char *)key);
    jstring jval = (*env)->NewStringUTF(env, g_variant_print((GVariant *)value, TRUE));
    (*env)->CallObjectMethod(env, map, put_method, jkey, jval);
    (*env)->DeleteLocalRef(env, jkey);
    (*env)->DeleteLocalRef(env, jval);
  }
  return map;
}

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_ApplicationList_size(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaApplicationList *list = (FridaApplicationList *) native_ptr;
  return (jint) frida_application_list_size(list);
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_ApplicationList_get(JNIEnv *env, jobject obj, jint index) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaApplicationList *list = (FridaApplicationList *) native_ptr;
  FridaApplication *app = frida_application_list_get(list, index);
  g_object_ref(app);
  jclass app_class = (*env)->FindClass(env, "nl/nl/axelkoolhaas/frida_java/Application");
  jmethodID app_ctor = (*env)->GetMethodID(env, app_class, "<init>", "(J)V");
  return (*env)->NewObject(env, app_class, app_ctor, (jlong) app);
}
