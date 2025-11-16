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

// ProcessList JNI implementations

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_ProcessList_size(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jfieldID native_ptr_field = (*env)->GetFieldID(env, cls, "nativePtr", "J");
  jlong native_ptr = (*env)->GetLongField(env, obj, native_ptr_field);
  if (native_ptr == 0) return 0;
  FridaProcessList *list = (FridaProcessList *) native_ptr;
  return (jint) frida_process_list_size(list);
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_ProcessList_get(JNIEnv *env, jobject obj, jint index) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jfieldID native_ptr_field = (*env)->GetFieldID(env, cls, "nativePtr", "J");
  jlong native_ptr = (*env)->GetLongField(env, obj, native_ptr_field);
  if (native_ptr == 0) return NULL;
  FridaProcessList *list = (FridaProcessList *) native_ptr;
  FridaProcess *process = frida_process_list_get(list, (gint) index);
  if (process == NULL) return NULL;
  g_object_ref(process); // Ensure Java owns a reference
  jclass process_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/Process");
  jmethodID process_ctor = (*env)->GetMethodID(env, process_class, "<init>", "(J)V");
  jobject result = (*env)->NewObject(env, process_class, process_ctor, (jlong) process);
  return result;
}

JNIEXPORT jobjectArray JNICALL Java_nl_axelkoolhaas_frida_1java_ProcessList_toArray(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jfieldID native_ptr_field = (*env)->GetFieldID(env, cls, "nativePtr", "J");
  jlong native_ptr = (*env)->GetLongField(env, obj, native_ptr_field);
  if (native_ptr == 0) return NULL;
  FridaProcessList *list = (FridaProcessList *) native_ptr;
  gint count = frida_process_list_size(list);
  jclass process_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/Process");
  jobjectArray array = (*env)->NewObjectArray(env, count, process_class, NULL);
  for (gint i = 0; i < count; i++) {
    FridaProcess *process = frida_process_list_get(list, i);
    if (process != NULL) {
      g_object_ref(process); // Ensure Java owns a reference
      jmethodID process_ctor = (*env)->GetMethodID(env, process_class, "<init>", "(J)V");
      jobject process_obj = (*env)->NewObject(env, process_class, process_ctor, (jlong) process);
      (*env)->SetObjectArrayElement(env, array, i, process_obj);
    }
  }
  return array;
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_ProcessList_disposeNative(JNIEnv *env, jobject obj, jlong native_ptr) {
  if (native_ptr != 0) {
    g_object_unref((FridaProcessList *) native_ptr);
  }
}
