#include <jni.h>
#include <frida-core.h>
#include <string.h>

/*
 * Class:     nl_axelkoolhaas_Frida
 * Method:    getVersionString
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_Frida_getVersionString
  (JNIEnv *env, jclass cls)
{
    const gchar *version = frida_version_string();
    return (*env)->NewStringUTF(env, version);
}

/*
 * Class:     nl_axelkoolhaas_Frida
 * Method:    getVersion
 * Signature: ()[I
 */
JNIEXPORT jintArray JNICALL Java_nl_axelkoolhaas_Frida_getVersion
  (JNIEnv *env, jclass cls)
{
    guint major, minor, micro, nano;
    frida_version(&major, &minor, &micro, &nano);

    jintArray result = (*env)->NewIntArray(env, 4);
    if (result == NULL) {
        return NULL; // out of memory error thrown
    }

    jint fill[4];
    fill[0] = (jint)major;
    fill[1] = (jint)minor;
    fill[2] = (jint)micro;
    fill[3] = (jint)nano;

    (*env)->SetIntArrayRegion(env, result, 0, 4, fill);
    return result;
}

/*
 * Class:     nl_axelkoolhaas_Frida
 * Method:    init
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_nl_axelkoolhaas_Frida_init
  (JNIEnv *env, jclass cls)
{
    frida_init();
}

/*
 * Class:     nl_axelkoolhaas_Frida
 * Method:    deinit
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_nl_axelkoolhaas_Frida_deinit
  (JNIEnv *env, jclass cls)
{
    frida_deinit();
}
