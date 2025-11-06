#include "frida_common.h"

/*
 * Session implementations
 */

/*
 * Class:     nl_axelkoolhaas_Session
 * Method:    getPid
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_Session_getPid
  (JNIEnv *env, jobject obj)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID getNativePtrMethod = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
    jlong nativePtr = (*env)->CallLongMethod(env, obj, getNativePtrMethod);

    FridaSession *session = (FridaSession*)nativePtr;
    return (jint)frida_session_get_pid(session);
}

/*
 * Class:     nl_axelkoolhaas_Session
 * Method:    isDetached
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_nl_axelkoolhaas_Session_isDetached
  (JNIEnv *env, jobject obj)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID getNativePtrMethod = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
    jlong nativePtr = (*env)->CallLongMethod(env, obj, getNativePtrMethod);

    FridaSession *session = (FridaSession*)nativePtr;
    return frida_session_is_detached(session) ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     nl_axelkoolhaas_Session
 * Method:    detach
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_nl_axelkoolhaas_Session_detach
  (JNIEnv *env, jobject obj)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID getNativePtrMethod = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
    jlong nativePtr = (*env)->CallLongMethod(env, obj, getNativePtrMethod);

    FridaSession *session = (FridaSession*)nativePtr;
    GError *error = NULL;

    frida_session_detach_sync(session, NULL, &error);

    if (error != NULL) {
        throw_runtime_exception(env, error->message);
        g_error_free(error);
    }
}

/*
 * Class:     nl_axelkoolhaas_Session
 * Method:    createScript
 * Signature: (Ljava/lang/String;)Lnl/axelkoolhaas/Script;
 */
JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_Session_createScript__Ljava_lang_String_2
  (JNIEnv *env, jobject obj, jstring source)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID getNativePtrMethod = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
    jlong nativePtr = (*env)->CallLongMethod(env, obj, getNativePtrMethod);

    FridaSession *session = (FridaSession*)nativePtr;
    const char *source_str = (*env)->GetStringUTFChars(env, source, NULL);
    GError *error = NULL;

    FridaScript *script = frida_session_create_script_sync(session, source_str, NULL, NULL, &error);

    (*env)->ReleaseStringUTFChars(env, source, source_str);

    if (error != NULL) {
        throw_runtime_exception(env, error->message);
        g_error_free(error);
        return NULL;
    }

    // Create Java Script object
    jclass script_class = (*env)->FindClass(env, "nl/axelkoolhaas/Script");
    jmethodID script_constructor = (*env)->GetMethodID(env, script_class, "<init>", "(J)V");
    return (*env)->NewObject(env, script_class, script_constructor, (jlong)script);
}

/*
 * Class:     nl_axelkoolhaas_Session
 * Method:    createScript
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Lnl/axelkoolhaas/Script;
 */
JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_Session_createScript__Ljava_lang_String_2Ljava_lang_String_2
  (JNIEnv *env, jobject obj, jstring source, jstring name)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID getNativePtrMethod = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
    jlong nativePtr = (*env)->CallLongMethod(env, obj, getNativePtrMethod);

    FridaSession *session = (FridaSession*)nativePtr;
    const char *source_str = (*env)->GetStringUTFChars(env, source, NULL);
    const char *name_str = (*env)->GetStringUTFChars(env, name, NULL);
    GError *error = NULL;

    // Create script options with name
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

    // Create Java Script object
    jclass script_class = (*env)->FindClass(env, "nl/axelkoolhaas/Script");
    jmethodID script_constructor = (*env)->GetMethodID(env, script_class, "<init>", "(J)V");
    return (*env)->NewObject(env, script_class, script_constructor, (jlong)script);
}

/*
 * Class:     nl_axelkoolhaas_Session
 * Method:    enableChildGating
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_nl_axelkoolhaas_Session_enableChildGating
  (JNIEnv *env, jobject obj)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID getNativePtrMethod = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
    jlong nativePtr = (*env)->CallLongMethod(env, obj, getNativePtrMethod);

    FridaSession *session = (FridaSession*)nativePtr;
    GError *error = NULL;

    frida_session_enable_child_gating_sync(session, NULL, &error);

    if (error != NULL) {
        throw_runtime_exception(env, error->message);
        g_error_free(error);
    }
}

/*
 * Class:     nl_axelkoolhaas_Session
 * Method:    disableChildGating
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_nl_axelkoolhaas_Session_disableChildGating
  (JNIEnv *env, jobject obj)
{
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID getNativePtrMethod = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
    jlong nativePtr = (*env)->CallLongMethod(env, obj, getNativePtrMethod);

    FridaSession *session = (FridaSession*)nativePtr;
    GError *error = NULL;

    frida_session_disable_child_gating_sync(session, NULL, &error);

    if (error != NULL) {
        throw_runtime_exception(env, error->message);
        g_error_free(error);
    }
}

/*
 * Class:     nl_axelkoolhaas_Session
 * Method:    disposeNative
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_nl_axelkoolhaas_Session_disposeNative
  (JNIEnv *env, jclass cls, jlong nativePtr)
{
    FridaSession *session = (FridaSession*)nativePtr;
    if (session != NULL) {
        // Try to detach first if not already detached
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
