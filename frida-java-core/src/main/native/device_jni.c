#include "frida_common.h"

// Device implementations

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_Device_getId(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDevice *device = (FridaDevice *) native_ptr;
  const gchar *id = frida_device_get_id(device);
  return (*env)->NewStringUTF(env, id);
}

JNIEXPORT jstring JNICALL Java_nl_axelkoolhaas_frida_1java_Device_getName(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDevice *device = (FridaDevice *) native_ptr;
  const gchar *name = frida_device_get_name(device);
  return (*env)->NewStringUTF(env, name);
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_Device_getType(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDevice *device = (FridaDevice *) native_ptr;
  FridaDeviceType type = frida_device_get_dtype(device);
  jclass type_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/Device$Type");
  jfieldID field_id;
  switch (type) {
    case FRIDA_DEVICE_TYPE_LOCAL:
      field_id = (*env)->GetStaticFieldID(env, type_class, "LOCAL", "Lnl/axelkoolhaas/frida_java/Device$Type;");
      break;
    case FRIDA_DEVICE_TYPE_REMOTE:
      field_id = (*env)->GetStaticFieldID(env, type_class, "REMOTE", "Lnl/axelkoolhaas/frida_java/Device$Type;");
      break;
    case FRIDA_DEVICE_TYPE_USB:
      field_id = (*env)->GetStaticFieldID(env, type_class, "USB", "Lnl/axelkoolhaas/frida_java/Device$Type;");
      break;
    default:
      field_id = (*env)->GetStaticFieldID(env, type_class, "LOCAL", "Lnl/axelkoolhaas/frida_java/Device$Type;");
      break;
  }
  return (*env)->GetStaticObjectField(env, type_class, field_id);
}

JNIEXPORT jboolean JNICALL Java_nl_axelkoolhaas_frida_1java_Device_isLost(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDevice *device = (FridaDevice *) native_ptr;
  return frida_device_is_lost(device) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_Device_attach(JNIEnv *env, jobject obj, jint pid) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDevice *device = (FridaDevice *) native_ptr;
  GError *error = NULL;
  FridaSession *session = frida_device_attach_sync(device, (guint) pid, NULL, NULL, &error);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
    return NULL;
  }
  jclass session_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/Session");
  jmethodID session_constructor = (*env)->GetMethodID(env, session_class, "<init>", "(J)V");
  return (*env)->NewObject(env, session_class, session_constructor, (jlong) session);
}

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_Device_spawn__Ljava_lang_String_2(JNIEnv *env, jobject obj, jstring program) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDevice *device = (FridaDevice *) native_ptr;
  const char *program_str = (*env)->GetStringUTFChars(env, program, NULL);
  GError *error = NULL;
  guint pid = frida_device_spawn_sync(device, program_str, NULL, NULL, &error);
  (*env)->ReleaseStringUTFChars(env, program, program_str);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
    return -1;
  }
  return (jint) pid;
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Device_resume(JNIEnv *env, jobject obj, jint pid) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDevice *device = (FridaDevice *) native_ptr;
  GError *error = NULL;
  frida_device_resume_sync(device, (guint) pid, NULL, &error);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
  }
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Device_kill(JNIEnv *env, jobject obj, jint pid) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDevice *device = (FridaDevice *) native_ptr;
  GError *error = NULL;
  frida_device_kill_sync(device, (guint) pid, NULL, &error);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
  }
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_Device_enumerateProcesses(JNIEnv *env, jobject obj) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDevice *device = (FridaDevice *) native_ptr;
  GError *error = NULL;
  FridaProcessList *processes = frida_device_enumerate_processes_sync(device, NULL, NULL, &error);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
    return NULL;
  }
  jclass process_list_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/ProcessList");
  jmethodID process_list_ctor = (*env)->GetMethodID(env, process_list_class, "<init>", "(J)V");
  jobject result = (*env)->NewObject(env, process_list_class, process_list_ctor, (jlong) processes);
  return result;
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_Device_attachByName(JNIEnv *env, jobject obj, jstring process_name) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDevice *device = (FridaDevice *) native_ptr;
  const char *process_name_str = (*env)->GetStringUTFChars(env, process_name, NULL);
  GError *error = NULL;
  FridaProcessList *processes = frida_device_enumerate_processes_sync(device, NULL, NULL, &error);
  if (error != NULL) {
    (*env)->ReleaseStringUTFChars(env, process_name, process_name_str);
    throw_runtime_exception(env, error->message);
    g_error_free(error);
    return NULL;
  }
  guint target_pid = 0;
  gint num_processes = frida_process_list_size(processes);
  for (gint i = 0; i < num_processes; i++) {
    FridaProcess *process = frida_process_list_get(processes, i);
    const gchar *name = frida_process_get_name(process);
    if (strstr(name, process_name_str) != NULL) {
      target_pid = frida_process_get_pid(process);
      g_object_unref(process);
      break;
    }
    g_object_unref(process);
  }
  frida_unref(processes);
  (*env)->ReleaseStringUTFChars(env, process_name, process_name_str);
  if (target_pid == 0) {
    throw_runtime_exception(env, "Process not found");
    return NULL;
  }
  FridaSession *session = frida_device_attach_sync(device, target_pid, NULL, NULL, &error);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
    return NULL;
  }
  jclass session_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/Session");
  jmethodID session_constructor = (*env)->GetMethodID(env, session_class, "<init>", "(J)V");
  return (*env)->NewObject(env, session_class, session_constructor, (jlong) session);
}

JNIEXPORT jint JNICALL Java_nl_axelkoolhaas_frida_1java_Device_spawn__Ljava_lang_String_2_3Ljava_lang_String_2(JNIEnv *env, jobject obj, jstring program, jobjectArray args) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
  jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
  FridaDevice *device = (FridaDevice *) native_ptr;
  const char *program_str = (*env)->GetStringUTFChars(env, program, NULL);
  GError *error = NULL;

  // Convert Java String[] args to gchar**
  gchar **argv = NULL;
  if (args != NULL) {
    jsize argc = (*env)->GetArrayLength(env, args);
    argv = g_new0(gchar *, argc + 2); // program + args + NULL
    argv[0] = g_strdup(program_str);
    for (jsize i = 0; i < argc; i++) {
      jstring arg = (jstring)(*env)->GetObjectArrayElement(env, args, i);
      const char *carg = (*env)->GetStringUTFChars(env, arg, NULL);
      argv[i + 1] = g_strdup(carg);
      (*env)->ReleaseStringUTFChars(env, arg, carg);
      (*env)->DeleteLocalRef(env, arg);
    }
    argv[argc + 1] = NULL;
  }

  // frida_device_spawn_sync with argv/options signature is not available in this Frida SDK version. JNI spawn functionality is disabled.
  /*
  FridaSpawnOptions *options = frida_spawn_options_new();
  guint pid = frida_device_spawn_sync(device, program_str, argv, options, &error);
  frida_unref(options);
  if (argv) {
    g_strfreev(argv);
  }
  (*env)->ReleaseStringUTFChars(env, program, program_str);
  if (error != NULL) {
    throw_runtime_exception(env, error->message);
    g_error_free(error);
    return -1;
  }
  return (jint) pid;
  */
  if (argv) {
    g_strfreev(argv);
  }
  (*env)->ReleaseStringUTFChars(env, program, program_str);
  return -1;
}

JNIEXPORT void JNICALL Java_nl_axelkoolhaas_frida_1java_Device_disposeNative(JNIEnv *env, jclass cls, jlong native_ptr) {
  FridaDevice *device = (FridaDevice *) native_ptr;
  if (device != NULL) {
    g_object_unref(device);
  }
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_Device_enumerateApplicationsSync(JNIEnv *env, jobject obj, jobject options, jobject cancellable) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
    jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
    FridaDevice *device = (FridaDevice *) native_ptr;
    GError *error = NULL;
    FridaApplicationList *applications = frida_device_enumerate_applications_sync(device, NULL, NULL, &error);
    if (error != NULL) {
        throw_runtime_exception(env, error->message);
        g_error_free(error);
        return NULL;
    }
    jclass application_list_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/ApplicationList");
    jmethodID application_list_ctor = (*env)->GetMethodID(env, application_list_class, "<init>", "(J)V");
    jobject result = (*env)->NewObject(env, application_list_class, application_list_ctor, (jlong) applications);
    return result;
}

JNIEXPORT jobject JNICALL Java_nl_axelkoolhaas_frida_1java_Device_enumerateProcessesSync(JNIEnv *env, jobject obj, jobject cancellable) {
    jclass cls = (*env)->GetObjectClass(env, obj);
    jmethodID get_native_ptr_method = (*env)->GetMethodID(env, cls, "getNativePtr", "()J");
    jlong native_ptr = (*env)->CallLongMethod(env, obj, get_native_ptr_method);
    FridaDevice *device = (FridaDevice *) native_ptr;
    GError *error = NULL;
    FridaProcessList *processes = frida_device_enumerate_processes_sync(device, NULL, NULL, &error);
    if (error != NULL) {
        throw_runtime_exception(env, error->message);
        g_error_free(error);
        return NULL;
    }
    jclass process_list_class = (*env)->FindClass(env, "nl/axelkoolhaas/frida_java/ProcessList");
    jmethodID process_list_ctor = (*env)->GetMethodID(env, process_list_class, "<init>", "(J)V");
    jobject result = (*env)->NewObject(env, process_list_class, process_list_ctor, (jlong) processes);
    return result;
}
