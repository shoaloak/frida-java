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

// This is the main Frida Java JNI implementation file
// It includes all the JNI implementations for Frida Java bindings

#include "frida_common.c"
#include "frida_jni.c"
#include "application_jni.c"
#include "application_query_options_jni.c"
#include "child_jni.c"
#include "device_manager_jni.c"
#include "device_jni.c"
#include "device_list_jni.c"
#include "frontmost_query_options_jni.c"
#include "process_jni.c"
#include "process_list_jni.c"
#include "process_match_options_jni.c"
#include "process_query_options_jni.c"
#include "remote_device_options_jni.c"
#include "script_jni.c"
#include "session_jni.c"
#include "session_options_jni.c"
#include "spawn_jni.c"
