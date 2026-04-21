package nl.axelkoolhaas.frida_java.frida;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;
import nl.axelkoolhaas.frida_java.util.GBytesUtil;
import nl.axelkoolhaas.frida_java.util.GErrorUtils;

/**
 * Portal service for collecting exposed gadgets and sessions.
 *
 * <p>A PortalService creates a portal that allows remote clients to connect, authenticate, and
 * interact with devices. It manages both cluster connections (for nodes) and control connections
 * (for controllers).
 *
 * <p>Usage:
 *
 * <pre>{@code
 * EndpointParameters clusterParams = EndpointParameters.builder()
 *     .address("0.0.0.0")
 *     .port(27042)
 *     .build();
 *
 * EndpointParameters controlParams = EndpointParameters.builder()
 *     .address("0.0.0.0")
 *     .port(27043)
 *     .build();
 *
 * PortalService portal = new PortalService(clusterParams, controlParams);
 * portal.start();
 *
 * // Handle signals
 * portal.on("node_connected", (Integer connectionId, String address) -> {
 *     System.out.println("Node connected: " + connectionId);
 * });
 *
 * // Send messages
 * portal.broadcast("{\"type\":\"hello\"}", null);
 *
 * // Later...
 * portal.stop();
 * portal.clean();
 * }</pre>
 */
public final class PortalService {
  private static final Logger log = LoggerFactory.getLogger(PortalService.class);

  private final MemorySegment portalPtr;

  // Native method handles
  private static final MethodHandle FRIDA_PORTAL_SERVICE_NEW;
  private static final MethodHandle FRIDA_PORTAL_SERVICE_GET_DEVICE;
  private static final MethodHandle FRIDA_PORTAL_SERVICE_GET_CLUSTER_PARAMS;
  private static final MethodHandle FRIDA_PORTAL_SERVICE_GET_CONTROL_PARAMS;
  private static final MethodHandle FRIDA_PORTAL_SERVICE_START_SYNC;
  private static final MethodHandle FRIDA_PORTAL_SERVICE_STOP_SYNC;
  private static final MethodHandle FRIDA_PORTAL_SERVICE_KICK;
  private static final MethodHandle FRIDA_PORTAL_SERVICE_POST;
  private static final MethodHandle FRIDA_PORTAL_SERVICE_NARROWCAST;
  private static final MethodHandle FRIDA_PORTAL_SERVICE_BROADCAST;
  private static final MethodHandle FRIDA_PORTAL_SERVICE_ENUMERATE_TAGS;
  private static final MethodHandle FRIDA_PORTAL_SERVICE_TAG;
  private static final MethodHandle FRIDA_PORTAL_SERVICE_UNTAG;

  static {
    Frida.ensureInitialized();
    FRIDA_PORTAL_SERVICE_NEW =
        FridaLibraryLoader.findFunction(
            "frida_portal_service_new",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS, // return FridaPortalService*
                ValueLayout.ADDRESS, // cluster_params
                ValueLayout.ADDRESS)); // control_params
    FRIDA_PORTAL_SERVICE_GET_DEVICE =
        FridaLibraryLoader.findFunction(
            "frida_portal_service_get_device",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_PORTAL_SERVICE_GET_CLUSTER_PARAMS =
        FridaLibraryLoader.findFunction(
            "frida_portal_service_get_cluster_params",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_PORTAL_SERVICE_GET_CONTROL_PARAMS =
        FridaLibraryLoader.findFunction(
            "frida_portal_service_get_control_params",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_PORTAL_SERVICE_START_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_portal_service_start_sync",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, // self
                ValueLayout.ADDRESS, // cancellable
                ValueLayout.ADDRESS)); // GError**
    FRIDA_PORTAL_SERVICE_STOP_SYNC =
        FridaLibraryLoader.findFunction(
            "frida_portal_service_stop_sync",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, // self
                ValueLayout.ADDRESS, // cancellable
                ValueLayout.ADDRESS)); // GError**
    FRIDA_PORTAL_SERVICE_KICK =
        FridaLibraryLoader.findFunction(
            "frida_portal_service_kick",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, // self
                ValueLayout.JAVA_INT)); // connection_id
    FRIDA_PORTAL_SERVICE_POST =
        FridaLibraryLoader.findFunction(
            "frida_portal_service_post",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, // self
                ValueLayout.JAVA_INT, // connection_id
                ValueLayout.ADDRESS, // json
                ValueLayout.ADDRESS)); // data (GBytes*)
    FRIDA_PORTAL_SERVICE_NARROWCAST =
        FridaLibraryLoader.findFunction(
            "frida_portal_service_narrowcast",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, // self
                ValueLayout.ADDRESS, // tag
                ValueLayout.ADDRESS, // json
                ValueLayout.ADDRESS)); // data (GBytes*)
    FRIDA_PORTAL_SERVICE_BROADCAST =
        FridaLibraryLoader.findFunction(
            "frida_portal_service_broadcast",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, // self
                ValueLayout.ADDRESS, // json
                ValueLayout.ADDRESS)); // data (GBytes*)
    FRIDA_PORTAL_SERVICE_ENUMERATE_TAGS =
        FridaLibraryLoader.findFunction(
            "frida_portal_service_enumerate_tags",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS, // return gchar**
                ValueLayout.ADDRESS, // self
                ValueLayout.JAVA_INT, // connection_id
                ValueLayout.ADDRESS)); // result_length (gint*)
    FRIDA_PORTAL_SERVICE_TAG =
        FridaLibraryLoader.findFunction(
            "frida_portal_service_tag",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, // self
                ValueLayout.JAVA_INT, // connection_id
                ValueLayout.ADDRESS)); // tag
    FRIDA_PORTAL_SERVICE_UNTAG =
        FridaLibraryLoader.findFunction(
            "frida_portal_service_untag",
            FunctionDescriptor.ofVoid(
                ValueLayout.ADDRESS, // self
                ValueLayout.JAVA_INT, // connection_id
                ValueLayout.ADDRESS)); // tag
  }

  /**
   * Creates a new portal service.
   *
   * @param clusterParams Endpoint parameters for cluster connections (nodes)
   * @param controlParams Endpoint parameters for control connections (controllers)
   */
  public PortalService(
      final EndpointParameters clusterParams, final EndpointParameters controlParams) {
    Objects.requireNonNull(clusterParams, "clusterParams");
    Objects.requireNonNull(controlParams, "controlParams");

    try {
      this.portalPtr =
          (MemorySegment)
              FRIDA_PORTAL_SERVICE_NEW.invokeExact(
                  clusterParams.getPointer(), controlParams.getPointer());

      if (portalPtr.address() == 0) {
        throw new FridaException("Failed to create PortalService");
      }
      log.debug("PortalService created");
    } catch (Throwable t) {
      log.debug("Failed to create PortalService", t);
      throw new FridaException("Failed to create PortalService", t);
    }
  }

  /**
   * Returns the device exposed by this portal.
   *
   * @return Device instance representing the portal device
   */
  public Device getDevice() {
    try {
      MemorySegment devicePtr =
          (MemorySegment) FRIDA_PORTAL_SERVICE_GET_DEVICE.invokeExact(portalPtr);
      if (devicePtr.address() == 0) {
        throw new FridaException("Failed to get device from PortalService");
      }
      return new Device(devicePtr);
    } catch (Throwable t) {
      log.debug("Failed to get device from PortalService", t);
      throw new FridaException("Failed to get device from PortalService", t);
    }
  }

  /**
   * Returns the cluster endpoint parameters.
   *
   * @return EndpointParameters for cluster connections
   */
  public EndpointParameters getClusterParams() {
    try {
      MemorySegment paramsPtr =
          (MemorySegment) FRIDA_PORTAL_SERVICE_GET_CLUSTER_PARAMS.invokeExact(portalPtr);
      if (paramsPtr.address() == 0) {
        throw new FridaException("Failed to get cluster params from PortalService");
      }
      return new EndpointParameters(paramsPtr);
    } catch (Throwable t) {
      log.debug("Failed to get cluster params from PortalService", t);
      throw new FridaException("Failed to get cluster params from PortalService", t);
    }
  }

  /**
   * Returns the control endpoint parameters.
   *
   * @return EndpointParameters for control connections
   */
  public EndpointParameters getControlParams() {
    try {
      MemorySegment paramsPtr =
          (MemorySegment) FRIDA_PORTAL_SERVICE_GET_CONTROL_PARAMS.invokeExact(portalPtr);
      if (paramsPtr.address() == 0) {
        throw new FridaException("Failed to get control params from PortalService");
      }
      return new EndpointParameters(paramsPtr);
    } catch (Throwable t) {
      log.debug("Failed to get control params from PortalService", t);
      throw new FridaException("Failed to get control params from PortalService", t);
    }
  }

  /**
   * Starts the portal service.
   *
   * <p>Begins accepting cluster and control connections on the configured endpoints.
   */
  public void start() {
    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      FRIDA_PORTAL_SERVICE_START_SYNC.invokeExact(portalPtr, MemorySegment.NULL, errorPtr);

      final MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      if (error.address() != 0) {
        GErrorUtils.handleError(error, "start PortalService");
      }
      log.debug("PortalService started");
    } catch (FridaException e) {
      throw e;
    } catch (Throwable t) {
      log.debug("Failed to start PortalService", t);
      throw new FridaException("Failed to start PortalService", t);
    }
  }

  /**
   * Stops the portal service.
   *
   * <p>Terminates all connections and stops accepting new connections.
   */
  public void stop() {
    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
      FRIDA_PORTAL_SERVICE_STOP_SYNC.invokeExact(portalPtr, MemorySegment.NULL, errorPtr);

      final MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
      if (error.address() != 0) {
        GErrorUtils.handleError(error, "stop PortalService");
      }
      log.debug("PortalService stopped");
    } catch (FridaException e) {
      throw e;
    } catch (Throwable t) {
      log.debug("Failed to stop PortalService", t);
      throw new FridaException("Failed to stop PortalService", t);
    }
  }

  /**
   * Kicks (disconnects) a specific connection.
   *
   * @param connectionId The connection ID to disconnect
   */
  public void kick(final int connectionId) {
    try {
      FRIDA_PORTAL_SERVICE_KICK.invokeExact(portalPtr, connectionId);
      log.trace("Kicked connection {}", connectionId);
    } catch (Throwable t) {
      log.debug("Failed to kick connection {}", connectionId, t);
      throw new FridaException("Failed to kick connection " + connectionId, t);
    }
  }

  /**
   * Posts a message to a specific connection.
   *
   * @param connectionId The connection ID to send to
   * @param json JSON message string
   * @param data Optional binary data (may be null)
   */
  public void post(final int connectionId, final String json, final byte[] data) {
    Objects.requireNonNull(json, "json");

    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment jsonPtr = arena.allocateFrom(json);
      final MemorySegment dataPtr =
          data != null ? GBytesUtil.createGBytes(data, arena) : MemorySegment.NULL;
      FRIDA_PORTAL_SERVICE_POST.invokeExact(portalPtr, connectionId, jsonPtr, dataPtr);
      log.trace("Posted message to connection {}", connectionId);
    } catch (Throwable t) {
      log.debug("Failed to post message to connection {}", connectionId, t);
      throw new FridaException("Failed to post message to connection " + connectionId, t);
    }
  }

  /**
   * Sends a message to all controllers tagged with the specified tag.
   *
   * @param tag Tag to filter recipients
   * @param json JSON message string
   * @param data Optional binary data (may be null)
   */
  public void narrowcast(final String tag, final String json, final byte[] data) {
    Objects.requireNonNull(tag, "tag");
    Objects.requireNonNull(json, "json");

    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment tagPtr = arena.allocateFrom(tag);
      final MemorySegment jsonPtr = arena.allocateFrom(json);
      final MemorySegment dataPtr =
          data != null ? GBytesUtil.createGBytes(data, arena) : MemorySegment.NULL;
      FRIDA_PORTAL_SERVICE_NARROWCAST.invokeExact(portalPtr, tagPtr, jsonPtr, dataPtr);
      log.trace("Narrowcast message to tag '{}'", tag);
    } catch (Throwable t) {
      log.debug("Failed to narrowcast message to tag '{}'", tag, t);
      throw new FridaException("Failed to narrowcast message to tag '" + tag + "'", t);
    }
  }

  /**
   * Broadcasts a message to all connected controllers.
   *
   * @param json JSON message string
   * @param data Optional binary data (may be null)
   */
  public void broadcast(final String json, final byte[] data) {
    Objects.requireNonNull(json, "json");

    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment jsonPtr = arena.allocateFrom(json);
      final MemorySegment dataPtr =
          data != null ? GBytesUtil.createGBytes(data, arena) : MemorySegment.NULL;
      FRIDA_PORTAL_SERVICE_BROADCAST.invokeExact(portalPtr, jsonPtr, dataPtr);
      log.trace("Broadcast message to all controllers");
    } catch (Throwable t) {
      log.debug("Failed to broadcast message", t);
      throw new FridaException("Failed to broadcast message", t);
    }
  }

  /**
   * Enumerates all tags associated with a connection.
   *
   * @param connectionId The connection ID to query
   * @return List of tag strings
   */
  public List<String> enumerateTags(final int connectionId) {
    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment lengthPtr = arena.allocate(ValueLayout.JAVA_INT);
      final MemorySegment tagsPtr =
          (MemorySegment)
              FRIDA_PORTAL_SERVICE_ENUMERATE_TAGS.invokeExact(portalPtr, connectionId, lengthPtr);

      final int length = lengthPtr.get(ValueLayout.JAVA_INT, 0);
      if (tagsPtr.address() == 0 || length == 0) {
        return List.of();
      }

      return FridaNativeUtils.cStringArrayToJavaList(tagsPtr, length);
    } catch (Throwable t) {
      log.debug("Failed to enumerate tags for connection {}", connectionId, t);
      throw new FridaException("Failed to enumerate tags for connection " + connectionId, t);
    }
  }

  /**
   * Tags a connection with a label.
   *
   * @param connectionId The connection ID to tag
   * @param tag The tag string to apply
   */
  public void tag(final int connectionId, final String tag) {
    Objects.requireNonNull(tag, "tag");

    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment tagPtr = arena.allocateFrom(tag);
      FRIDA_PORTAL_SERVICE_TAG.invokeExact(portalPtr, connectionId, tagPtr);
      log.trace("Tagged connection {} with '{}'", connectionId, tag);
    } catch (Throwable t) {
      log.debug("Failed to tag connection {} with '{}'", connectionId, tag, t);
      throw new FridaException(
          "Failed to tag connection " + connectionId + " with '" + tag + "'", t);
    }
  }

  /**
   * Removes a tag from a connection.
   *
   * @param connectionId The connection ID to untag
   * @param tag The tag string to remove
   */
  public void untag(final int connectionId, final String tag) {
    Objects.requireNonNull(tag, "tag");

    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment tagPtr = arena.allocateFrom(tag);
      FRIDA_PORTAL_SERVICE_UNTAG.invokeExact(portalPtr, connectionId, tagPtr);
      log.trace("Untagged connection {} from '{}'", connectionId, tag);
    } catch (Throwable t) {
      log.debug("Failed to untag connection {} from '{}'", connectionId, tag, t);
      throw new FridaException(
          "Failed to untag connection " + connectionId + " from '" + tag + "'", t);
    }
  }

  /**
   * Connects to portal signals.
   *
   * <p>Available signals:
   *
   * <ul>
   *   <li>"node_connected" - callback receives (Integer connectionId, String address)
   *   <li>"node_joined" - callback receives (Integer connectionId, Application app)
   *   <li>"node_left" - callback receives (Integer connectionId, Application app)
   *   <li>"node_disconnected" - callback receives (Integer connectionId, String address)
   *   <li>"controller_connected" - callback receives (Integer connectionId, String address)
   *   <li>"controller_disconnected" - callback receives (Integer connectionId, String address)
   *   <li>"authenticated" - callback receives (Integer connectionId, String sessionInfo)
   *   <li>"subscribe" - callback receives (Integer connectionId)
   *   <li>"message" - callback receives (Integer connectionId, String json, byte[] data)
   * </ul>
   *
   * @param signalName Signal name
   * @param callback Callback function matching the signal signature
   */
  public void on(final String signalName, final Object callback) {
    Objects.requireNonNull(signalName, "signalName");
    Objects.requireNonNull(callback, "callback");

    Closure.connectClosure(portalPtr, signalName, callback);
    log.debug("Connected signal '{}' to PortalService", signalName);
  }

  /** Cleans resources held by the portal service. */
  public void clean() {
    FridaNativeUtils.fridaUnref(portalPtr);
  }

  @Override
  public String toString() {
    return String.format("<PortalService: %s>", Objects.toIdentityString(portalPtr));
  }
}
