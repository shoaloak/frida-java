#include "frida_common.h"

// Script implementations

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_Script_load(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaScript *script = (FridaScript *) native_ptr;
  GError *error = NULL;
  frida_script_load_sync(script, NULL, &error);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
  }
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_Script_unload(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaScript *script = (FridaScript *) native_ptr;
  GError *error = NULL;
  frida_script_unload_sync(script, NULL, &error);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
  }
}

JNIEXPORT jboolean JNICALL Java_nl_axelkoolhaas_Script_isDestroyed(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaScript *script = (FridaScript *) native_ptr;
  return frida_script_is_destroyed(script) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_Script_post__Ljava_lang_String_2(JNIEnv *env, jobject obj, jstring message) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaScript *script = (FridaScript *) native_ptr;
  const char *message_str = (*env)->GetStringUTFChars(env, message, NULL);
  frida_script_post(script, message_str, NULL);
  (*env)->ReleaseStringUTFChars(env, message, message_str);
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_Script_post__Ljava_lang_String_2_3B(JNIEnv *env, jobject obj, jstring message, jbyteArray data) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaScript *script = (FridaScript *) native_ptr;
  const char *message_str = (*env)->GetStringUTFChars(env, message, NULL);
  GBytes *bytes_data = NULL;
  if (data != NULL) {
    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
    bytes_data = g_bytes_new(data_bytes, data_len);
    (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);
  }
  frida_script_post(script, message_str, bytes_data);
  if (bytes_data != NULL) {
    g_bytes_unref(bytes_data);
  }
  (*env)->ReleaseStringUTFChars(env, message, message_str);
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_Script_setMessageHandler(JNIEnv *env, jobject obj, jobject handler) {
  // TODO: Implement message handler support
  // This requires setting up GObject signal connections and JNI global refs
  // For now, we'll leave this as a stub
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_Script_disposeNative(JNIEnv *env, jclass cls, jlong native_ptr) {
  FridaScript *script = (FridaScript *) native_ptr;
  if (script != NULL) {
    if (!frida_script_is_destroyed(script)) {
      GError *error = NULL;
      frida_script_unload_sync(script, NULL, &error);
      if (error != NULL) {
        g_error_free(error);
      }
    }
    g_object_unref(script);
  }
}
