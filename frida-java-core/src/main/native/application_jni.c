/*
 * Copyright (C) 2025 Axel Koolhaas
 *
 * This file is part of frida-java.
 *
 * frida-java is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * frida-java is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with frida-java.  If not, see <https://www.gnu.org/licenses/>.
 */

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
  jclass app_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/Application");
  jmethodID app_ctor = (*env)->GetMethodID(env, app_class, "<init>", "(J)V");
  return (*env)->NewObject(env, app_class, app_ctor, (jlong) app);
}

JNIEXPORT jobjectArray JNICALL Java_nl_axelkoolhaas_frida_1java_ApplicationList_toArray(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaApplicationList *list = (FridaApplicationList *) native_ptr;

  gint size = frida_application_list_size(list);
  jclass app_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/Application");
  jobjectArray result = (*env)->NewObjectArray(env, size, app_class, NULL);

  for (gint i = 0; i < size; i++) {
    FridaApplication *app = frida_application_list_get(list, i);
    g_object_ref(app);
    jmethodID app_ctor = (*env)->GetMethodID(env, app_class, "<init>", "(J)V");
    jobject app_obj = (*env)->NewObject(env, app_class, app_ctor, (jlong) app);
    (*env)->SetObjectArrayElement(env, result, i, app_obj);
    (*env)->DeleteLocalRef(env, app_obj);
  }

  return result;
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_ApplicationList_disposeNative(JNIEnv *env, jobject obj, jlong native_ptr) {
  FridaApplicationList *list = (FridaApplicationList *) native_ptr;
  if (list != NULL) {
    g_object_unref(list);
  }
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Application_disposeNative(JNIEnv *env, jobject obj, jlong native_ptr) {
  FridaApplication *app = (FridaApplication *) native_ptr;
  if (app != NULL) {
    g_object_unref(app);
  }
}

