#include "frida_common.h"

// DeviceManager implementations

JNIEXPORT jlong JNICALL Java_nl_axelkoolhaas_frida_1java_DeviceManager_createNative(JNIEnv *env, jobject obj) {
  FridaDeviceManager *manager = frida_device_manager_new();
  return (jlong) manager;
}

JNIEXPORT jobjectArray JNICALL Java_nl_axelkoolhaas_frida_1java_DeviceManager_enumerateDevices(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDeviceManager *manager = (FridaDeviceManager *) native_ptr;
  GError *error = NULL;
  FridaDeviceList *devices = frida_device_manager_enumerate_devices_sync(manager, NULL, &error);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
    return NULL;
  }
  gint num_devices = frida_device_list_size(devices);
  jclass device_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/Device");
  jmethodID device_constructor = (*env)->GetMethodID(env, device_class, "<init>", "(J)V");
  jobjectArray result = (*env)->NewObjectArray(env, num_devices, device_class, NULL);
  for (gint i = 0; i < num_devices; i++) {
    FridaDevice *device = frida_device_list_get(devices, i);
    g_object_ref(device);
    jobject java_device = (*env)->NewObject(env, device_class, device_constructor, (jlong) device);
    (*env)->SetObjectArrayElement(env, result, i, java_device);
  }
  frida_unref(devices);
  return result;
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_DeviceManager_closeNative(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDeviceManager *manager = (FridaDeviceManager *) native_ptr;
  if (manager != NULL) {
    frida_device_manager_close_sync(manager, NULL, NULL);
    frida_unref(manager);
  }
}

JNIEXPORT jlong JNICALL Java_nl_axelkoolhaas_frida_1java_DeviceManager_getDeviceById(JNIEnv *env, jobject obj, jstring id) {
  // frida_device_manager_get_device_by_id_sync is not available in this Frida SDK version.
  return 0;
}

JNIEXPORT jlong JNICALL Java_nl_axelkoolhaas_frida_1java_DeviceManager_getDeviceByType(JNIEnv *env, jobject obj, jint type) {
  // frida_device_manager_get_device_by_type_sync is not available in this Frida SDK version.
  return 0;
}

JNIEXPORT jlong JNICALL Java_nl_axelkoolhaas_frida_1java_DeviceManager_findDeviceById(JNIEnv *env, jobject obj, jstring id) {
  // frida_device_manager_find_device_by_id_sync is not available in this Frida SDK version.
  return 0;
}
