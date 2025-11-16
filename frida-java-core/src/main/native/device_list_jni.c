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

// DeviceList JNI implementations

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_DeviceList_size(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDeviceList *list = (FridaDeviceList *) native_ptr;
  if (list == NULL) return 0;
  return (jint) frida_device_list_size(list);
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_DeviceList_get(JNIEnv *env, jobject obj, jint index) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDeviceList *list = (FridaDeviceList *) native_ptr;
  if (list == NULL) return NULL;
  FridaDevice *device = frida_device_list_get(list, index);
  if (device == NULL) return NULL;
  g_object_ref(device);
  jclass device_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/Device");
  jmethodID device_ctor = (*env)->GetMethodID(env, device_class, "<init>", "(J)V");
  return (*env)->NewObject(env, device_class, device_ctor, (jlong) device);
}
