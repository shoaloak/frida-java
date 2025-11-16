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
