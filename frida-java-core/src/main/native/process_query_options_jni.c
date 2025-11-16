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
