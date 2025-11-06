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
