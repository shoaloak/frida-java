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

package nl.axelkoolhaas.frida_java.frida;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.util.GErrorUtils;

/** Device manager for enumerating and managing Frida devices */
public class DeviceManager implements AutoCloseable {
  private static final Logger log = LoggerFactory.getLogger(DeviceManager.class);
  private final MemorySegment managerPtr;

  private static final MethodHandle FRIDA_DEVICE_MANAGER_NEW;
  private static final MethodHandle FRIDA_DEVICE_MANAGER_ENUMERATE_DEVICES_SYNC;
  private static final MethodHandle FRIDA_DEVICE_MANAGER_ADD_REMOTE_DEVICE_SYNC;
  private static final MethodHandle FRIDA_DEVICE_MANAGER_REMOVE_REMOTE_DEVICE_SYNC;
  private static final MethodHandle FRIDA_DEVICE_LIST_SIZE;
  private static final MethodHandle FRIDA_DEVICE_LIST_GET;
  private static final MethodHandle FRIDA_DEVICE_MANAGER_CLOSE_SYNC;

  // Using pure Java filtering, as the native method seems to have issues in some environments
  //    private static final MethodHandle FRIDA_DEVICE_MANAGER_GET_DEVICE_BY_ID_SYNC;

  static {
    Frida.ensureInitialized();

    FRIDA_DEVICE_MANAGER_NEW =
        FridaLibraryLoader.findFunction(
            "frida_device_manager_new", FunctionDescriptor.of(ValueLayout.ADDRESS));
    FRIDA_DEVICE_MANAGER_ENUMERATE_DEVICES_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_device_manager_enumerate_devices_sync",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
    FRIDA_DEVICE_MANAGER_ADD_REMOTE_DEVICE_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_device_manager_add_remote_device_sync",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
    FRIDA_DEVICE_MANAGER_REMOVE_REMOTE_DEVICE_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_device_manager_remove_remote_device_sync",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS,
                ValueLayout.ADDRESS));
    FRIDA_DEVICE_LIST_SIZE =
        FridaLibraryLoader.findFunction(
            "frida_device_list_size",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    FRIDA_DEVICE_LIST_GET =
        FridaLibraryLoader.findFunction(
            "frida_device_list_get",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    FRIDA_DEVICE_MANAGER_CLOSE_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_device_manager_close_sync",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
  }

  public DeviceManager() {
    log.debug("Creating DeviceManager");
    try {
      MemorySegment managerPtr = (MemorySegment) FRIDA_DEVICE_MANAGER_NEW.invoke();
      this.managerPtr = FridaNativeUtils.requireValidPointer(managerPtr, "Device manager pointer");
      log.debug("DeviceManager created successfully");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to create DeviceManager: {}", e.getMessage(), e);
      throw new FridaException("Failed to initialize device manager", e);
    }
  }

  /**
   * Enumerate all available devices
   *
   * @return List of Device objects
   */
  public List<Device> enumerateDevices() {
    log.trace("Enumerating devices");
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      MemorySegment deviceList =
          (MemorySegment)
              FRIDA_DEVICE_MANAGER_ENUMERATE_DEVICES_SYNC.invoke(
                  managerPtr, MemorySegment.NULL, errorPtr);

      // Check for errors
      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "enumerate devices");

      if (deviceList.equals(MemorySegment.NULL)) {
        log.debug("No devices found");
        return new ArrayList<>();
      }

      try {
        List<Device> devices = extractDevicesFromList(deviceList);
        log.debug("Found {} device(s)", devices.size());
        return devices;
      } finally {
        FridaNativeUtils.fridaUnref(deviceList);
      }
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to enumerate devices: {}", e.getMessage(), e);
      throw new FridaException("Failed to enumerate devices", e);
    }
  }

  /**
   * Get the local device
   *
   * @return Optional containing the local Device, or empty if not found
   */
  public Optional<Device> getLocalDevice() {
    List<Device> devices = enumerateDevices();
    return devices.stream().filter(device -> device.getType() == DeviceType.LOCAL).findFirst();
  }

  @SuppressWarnings("unused")
  public Optional<Device> getUsbDevice() {
    List<Device> devices = enumerateDevices();
    return devices.stream().filter(device -> device.getType() == DeviceType.USB).findFirst();
  }

  /**
   * Get a device by its ID
   *
   * @param deviceId The device ID to look for
   * @return Optional containing the Device, or empty if not found
   */
  public Optional<Device> getDeviceById(String deviceId) {
    List<Device> devices = enumerateDevices();
    return devices.stream().filter(device -> deviceId.equals(device.getId())).findFirst();
  }

  /**
   * Get a device by its name
   *
   * @param deviceName The device name to look for
   * @return Optional containing the Device, or empty if not found
   */
  public Optional<Device> getDeviceByName(String deviceName) {
    List<Device> devices = enumerateDevices();
    return devices.stream().filter(device -> deviceName.equals(device.getName())).findFirst();
  }

  /**
   * Register callbacks for device manager events
   *
   * <p>Available signals: - "added": Emitted when a device is added Callback should be
   * SignalCallbacks.DeviceCallback accepting (Device device) - "removed": Emitted when a device is
   * removed Callback should be SignalCallbacks.DeviceCallback accepting (Device device) -
   * "changed": Emitted when the device list changes Callback should be SignalCallbacks.VoidCallback
   * or Runnable
   *
   * @param signalName Signal name to connect to
   * @param callback Callback function
   * @throws IllegalArgumentException if signal name is unknown or callback type is invalid
   */
  public void on(String signalName, Object callback) {
    if (callback == null) {
      throw new IllegalArgumentException("Callback cannot be null");
    }

    log.debug("Registering callback for device manager signal: {}", signalName);

    switch (signalName) {
      case "added":
      case "removed":
        if (!(callback instanceof SignalCallbacks.DeviceCallback)) {
          throw new IllegalArgumentException(
              signalName + " signal callback must be DeviceCallback");
        }
        break;
      case "changed":
        if (!(callback instanceof SignalCallbacks.VoidCallback)
            && !(callback instanceof Runnable)) {
          throw new IllegalArgumentException(
              "changed signal callback must be VoidCallback or Runnable");
        }
        break;
      default:
        throw new IllegalArgumentException("Unknown signal: " + signalName);
    }

    // Actually connect the closure to the GLib signal
    try {
      long handlerId = Closure.connectClosure(managerPtr, signalName, callback);

      if (handlerId > 0) {
        log.trace("Connected device manager signal '{}' with handler ID {}", signalName, handlerId);
      } else {
        log.warn(
            "Failed to connect device manager signal '{}' - no handler ID returned", signalName);
      }
    } catch (Throwable e) {
      log.debug("Failed to connect device manager signal '{}': {}", signalName, e.getMessage());
      throw new FridaException("Failed to connect device manager signal '" + signalName + "'", e);
    }

    log.trace("Registered callback for device manager signal '{}'", signalName);
  }

  /**
   * Add a remote device at the specified address
   *
   * @param address Address of the remote device (e.g., "192.168.1.100:27042")
   * @return Device object representing the remote device
   * @throws FridaException if adding the remote device fails
   */
  public Device addRemoteDevice(String address) {
    return addRemoteDevice(address, null);
  }

  /**
   * Add a remote device at the specified address with options.
   *
   * @param address Address of the remote device (e.g., "192.168.1.100:27042")
   * @param options Remote device options, or null for defaults
   * @return Device object representing the remote device
   * @throws FridaException if adding the remote device fails
   */
  public Device addRemoteDevice(String address, RemoteDeviceOptions options) {
    log.debug("Adding remote device at address: {}", address);
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment addressPtr = arena.allocateFrom(address);
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      MemorySegment optionsPtr = options != null ? options.getPointer() : MemorySegment.NULL;
      MemorySegment devicePtr =
          (MemorySegment)
              FRIDA_DEVICE_MANAGER_ADD_REMOTE_DEVICE_SYNC.invoke(
                  managerPtr, addressPtr, optionsPtr, MemorySegment.NULL, errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "add remote device");

      log.debug("Successfully added remote device at {}", address);
      return new Device(devicePtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to add remote device at '{}': {}", address, e.getMessage());
      throw new FridaException("Failed to add remote device at: " + address, e);
    }
  }

  /**
   * Remove a remote device at the specified address
   *
   * @param address Address of the remote device to remove
   * @throws FridaException if removing the remote device fails
   */
  public void removeRemoteDevice(String address) {
    log.debug("Removing remote device at address: {}", address);
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment addressPtr = arena.allocateFrom(address);
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      FRIDA_DEVICE_MANAGER_REMOVE_REMOTE_DEVICE_SYNC.invoke(
          managerPtr, addressPtr, MemorySegment.NULL, errorPtr);

      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "remove remote device");

      log.debug("Successfully removed remote device at {}", address);
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to remove remote device at '{}': {}", address, e.getMessage());
      throw new FridaException("Failed to remove remote device at: " + address, e);
    }
  }

  public void clean() {
    log.debug("Closing DeviceManager");
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      errorPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);

      FRIDA_DEVICE_MANAGER_CLOSE_SYNC.invoke(managerPtr, MemorySegment.NULL, errorPtr);

      // Check for errors
      MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      GErrorUtils.handleError(error, "clean device manager");
      log.debug("DeviceManager closed successfully");
    } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
      throw e;
    } catch (Throwable e) {
      log.debug("Failed to close DeviceManager: {}", e.getMessage(), e);
      throw new FridaException("Failed to clean device manager", e);
    }
  }

  @Override
  public void close() {
    clean();
  }

  /**
   * Get the native pointer to the device manager. Used internally by other Frida classes (e.g.,
   * Compiler).
   */
  MemorySegment getPointer() {
    return managerPtr;
  }

  /** Extract Device objects from the native device list */
  private List<Device> extractDevicesFromList(MemorySegment deviceList) throws Throwable {
    int deviceCount = (int) FRIDA_DEVICE_LIST_SIZE.invoke(deviceList);
    List<Device> devices = new ArrayList<>(deviceCount);

    for (int i = 0; i < deviceCount; i++) {
      MemorySegment devicePtr = (MemorySegment) FRIDA_DEVICE_LIST_GET.invoke(deviceList, i);
      if (!devicePtr.equals(MemorySegment.NULL)) {
        // Keep each device alive after releasing the list.
        FridaNativeUtils.fridaRef(devicePtr);
        devices.add(new Device(devicePtr));
      }
    }

    return devices;
  }
}
