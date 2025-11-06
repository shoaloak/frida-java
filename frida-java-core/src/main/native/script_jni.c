#include "frida_common.h"

// Helper struct to hold JNI references for the message handler
typedef struct {
  JavaVM *jvm;
  jobject handler_global;
} ScriptMessageHandlerData;

static void on_frida_script_message(FridaScript *script, const gchar *message, GBytes *data, gpointer user_data) {
  ScriptMessageHandlerData *handler_data = (ScriptMessageHandlerData *)user_data;
  if (!handler_data || !handler_data->handler_global) return;
  JNIEnv *env = NULL;
  if ((*handler_data->jvm)->AttachCurrentThread(handler_data->jvm, (void **)&env, NULL) != 0) return;
  jclass handler_class = (*env)->GetObjectClass(env, handler_data->handler_global);
  jmethodID on_message = (*env)->GetMethodID(env, handler_class, "onMessage", "(Ljava/lang/String;[B)V");
  if (!on_message) return;
  jstring jmsg = (*env)->NewStringUTF(env, message ? message : "");
  jbyteArray jdata = NULL;
  if (data) {
    gsize size = 0;
    const guint8 *bytes = g_bytes_get_data(data, &size);
    jdata = (*env)->NewByteArray(env, (jsize)size);
    if (jdata && size > 0) {
      (*env)->SetByteArrayRegion(env, jdata, 0, (jsize)size, (const jbyte *)bytes);
    }
  }
  (*env)->CallVoidMethod(env, handler_data->handler_global, on_message, jmsg, jdata);
  (*env)->DeleteLocalRef(env, jmsg);
  if (jdata) (*env)->DeleteLocalRef(env, jdata);
}

// Script implementations

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Script_load(JNIEnv *env, jobject obj) {
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

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Script_unload(JNIEnv *env, jobject obj) {
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

JNIEXPORT jboolean JNICALL Java_nl_axelkoolhaas_frida_1java_Script_isDestroyed(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaScript *script = (FridaScript *) native_ptr;
  return frida_script_is_destroyed(script) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Script_post__Ljava_lang_String_2(JNIEnv *env, jobject obj, jstring message) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaScript *script = (FridaScript *) native_ptr;
  const char *message_str = (*env)->GetStringUTFChars(env, message, NULL);
  frida_script_post(script, message_str, NULL);
  (*env)->ReleaseStringUTFChars(env, message, message_str);
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Script_post__Ljava_lang_String_2_3B(JNIEnv *env, jobject obj, jstring message, jbyteArray data) {
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

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Script_setMessageHandler(JNIEnv *env, jobject obj, jobject handler) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaScript *script = (FridaScript *) native_ptr;

  // Remove any previous handler (not implemented: would need to store handler_data pointer)

  if (handler == NULL) return;

  ScriptMessageHandlerData *handler_data = g_new0(ScriptMessageHandlerData, 1);
  if ((*env)->GetJavaVM(env, &handler_data->jvm) != 0) {
    g_free(handler_data);
    return;
  }
  handler_data->handler_global = (*env)->NewGlobalRef(env, handler);

  g_signal_connect_data(script, "message", G_CALLBACK(on_frida_script_message), handler_data, (GClosureNotify)g_free, 0);
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Script_disposeNative(JNIEnv *env, jclass cls, jlong native_ptr) {
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

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_Script_getName(JNIEnv *env, jobject obj) {
  // frida_script_get_name is not available in this Frida SDK version.
  return NULL;
}
