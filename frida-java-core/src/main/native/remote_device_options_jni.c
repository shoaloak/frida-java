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

// RemoteDeviceOptions JNI implementations

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_RemoteDeviceOptions_setOrigin(JNIEnv *env, jobject obj, jstring value) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaRemoteDeviceOptions *opts = (FridaRemoteDeviceOptions *) native_ptr;
  const char *corigin = (*env)->GetStringUTFChars(env, value, 0);
  g_object_set(opts, "origin", corigin, NULL);
  (*env)->ReleaseStringUTFChars(env, value, corigin);
}

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_RemoteDeviceOptions_getOrigin(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaRemoteDeviceOptions *opts = (FridaRemoteDeviceOptions *) native_ptr;
  gchar *origin = NULL;
  g_object_get(opts, "origin", &origin, NULL);
  jstring result = origin ? (*env)->NewStringUTF(env, origin) : NULL;
  g_free(origin);
  return result;
}
