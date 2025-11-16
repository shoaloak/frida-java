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

// Session implementations

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_Session_getPid(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaSession *session = (FridaSession *) native_ptr;
  return (jint) frida_session_get_pid(session);
}

JNIEXPORT jboolean JNICALL Java_nl_axelkoolhaas_frida_1java_Session_isDetached(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaSession *session = (FridaSession *) native_ptr;
  return frida_session_is_detached(session) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Session_detach(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaSession *session = (FridaSession *) native_ptr;
  GError *error = NULL;
  frida_session_detach_sync(session, NULL, &error);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
  }
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_Session_createScript__Ljava_lang_String_2(JNIEnv *env, jobject obj, jstring source) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaSession *session = (FridaSession *) native_ptr;
  const char *source_str = (*env)->GetStringUTFChars(env, source, NULL);
  GError *error = NULL;
  FridaScript *script = frida_session_create_script_sync(session, source_str, NULL, NULL, &error);
  (*env)->ReleaseStringUTFChars(env, source, source_str);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
    return NULL;
  }
  jclass script_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/Script");
  jmethodID script_constructor = (*env)->GetMethodID(env, script_class, "<init>", "(J)V");
  return (*env)->NewObject(env, script_class, script_constructor, (jlong) script);
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_Session_createScript__Ljava_lang_String_2Ljava_lang_String_2(JNIEnv *env, jobject obj, jstring source, jstring name) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaSession *session = (FridaSession *) native_ptr;
  const char *source_str = (*env)->GetStringUTFChars(env, source, NULL);
  const char *name_str = (*env)->GetStringUTFChars(env, name, NULL);
  GError *error = NULL;
  FridaScriptOptions *options = frida_script_options_new();
  frida_script_options_set_name(options, name_str);
  FridaScript *script = frida_session_create_script_sync(session, source_str, options, NULL, &error);
  g_object_unref(options);
  (*env)->ReleaseStringUTFChars(env, source, source_str);
  (*env)->ReleaseStringUTFChars(env, name, name_str);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
    return NULL;
  }
  jclass script_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/Script");
  jmethodID script_constructor = (*env)->GetMethodID(env, script_class, "<init>", "(J)V");
  return (*env)->NewObject(env, script_class, script_constructor, (jlong) script);
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Session_enableChildGating(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaSession *session = (FridaSession *) native_ptr;
  GError *error = NULL;
  frida_session_enable_child_gating_sync(session, NULL, &error);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
  }
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Session_disableChildGating(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaSession *session = (FridaSession *) native_ptr;
  GError *error = NULL;
  frida_session_disable_child_gating_sync(session, NULL, &error);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
  }
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_Session_getDevice(JNIEnv *env, jobject obj) {
  // frida_session_get_device is not available in this Frida SDK version.
  return NULL;
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_Session_getParameters(JNIEnv *env, jobject obj) {
  // Not implemented: FridaSession parameters not exposed in C API
  return NULL;
}

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_Session_getRealm(JNIEnv *env, jobject obj) {
  // Not implemented: FridaSession realm not exposed in C API
  return NULL;
}

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_Session_getPersistTimeout(JNIEnv *env, jobject obj) {
  // Not implemented: FridaSession persist-timeout not exposed in C API
  return 0;
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Session_disposeNative(JNIEnv *env, jclass cls, jlong native_ptr) {
  FridaSession *session = (FridaSession *) native_ptr;
  if (session != NULL) {
    if (!frida_session_is_detached(session)) {
      GError *error = NULL;
      frida_session_detach_sync(session, NULL, &error);
      if (error != NULL) {
        g_error_free(error);
      }
    }
    g_object_unref(session);
  }
}
