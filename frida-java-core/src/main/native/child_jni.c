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

// Child JNI implementations

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_Child_getPid(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaChild *child = (FridaChild *) native_ptr;
  return (jint) frida_child_get_pid(child);
}

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_Child_getParentPid(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaChild *child = (FridaChild *) native_ptr;
  return (jint) frida_child_get_parent_pid(child);
}

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_Child_getOrigin(JNIEnv *env, jobject obj) {
  // frida_child_get_origin is not available in this Frida SDK version.
  return NULL;
}

JNIEXPORT jobjectArray JNICALL Java_nl_axelkoolhaas_frida_1java_Child_getArgv(JNIEnv *env, jobject obj) {
  // frida_child_get_argv is not available in this Frida SDK version.
  return NULL;
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_Child_getEnv(JNIEnv *env, jobject obj) {
  // frida_child_get_env/frida_child_get_envp is not available in this Frida SDK version.
  return NULL;
}

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_ChildList_size(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaChildList *list = (FridaChildList *) native_ptr;
  return (jint) frida_child_list_size(list);
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_ChildList_get(JNIEnv *env, jobject obj, jint index) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaChildList *list = (FridaChildList *) native_ptr;
  FridaChild *child = frida_child_list_get(list, index);
  g_object_ref(child);
  jclass child_class = (*env)->FindClass(env, "nl/nl/axelkoolhaas/frida_java/Child");
  jmethodID child_ctor = (*env)->GetMethodID(env, child_class, "<init>", "(J)V");
  return (*env)->NewObject(env, child_class, child_ctor, (jlong) child);
}
