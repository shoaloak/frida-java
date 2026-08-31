package nl.axelkoolhaas.frida_java.frida;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;

/**
 * Configuration parameters for creating portal endpoints.
 *
 * <p>EndpointParameters specify network and security settings for portal cluster and control
 * endpoints, including address, port, TLS certificate, origin restrictions, authentication, and
 * asset serving.
 */
public final class EndpointParameters {
  private static final Logger log = LoggerFactory.getLogger(EndpointParameters.class);

  private final MemorySegment paramsPtr;

  // Native method handles
  private static final MethodHandle FRIDA_ENDPOINT_PARAMETERS_NEW;
  private static final MethodHandle FRIDA_ENDPOINT_PARAMETERS_GET_ADDRESS;
  private static final MethodHandle FRIDA_ENDPOINT_PARAMETERS_GET_PORT;
  private static final MethodHandle FRIDA_ENDPOINT_PARAMETERS_GET_CERTIFICATE;
  private static final MethodHandle FRIDA_ENDPOINT_PARAMETERS_GET_ORIGIN;
  private static final MethodHandle FRIDA_ENDPOINT_PARAMETERS_GET_AUTH_SERVICE;
  private static final MethodHandle FRIDA_ENDPOINT_PARAMETERS_GET_ASSET_ROOT;
  private static final MethodHandle FRIDA_ENDPOINT_PARAMETERS_SET_ASSET_ROOT;
  private static final MethodHandle FRIDA_STATIC_AUTHENTICATION_SERVICE_NEW;
  private static final MethodHandle G_TLS_CERTIFICATE_NEW_FROM_FILE;
  private static final MethodHandle G_FILE_NEW_FOR_PATH;
  private static final MethodHandle G_FILE_GET_PATH;

  static {
    Frida.ensureInitialized();
    FRIDA_ENDPOINT_PARAMETERS_NEW =
        FridaLibraryLoader.findFunction(
            "frida_endpoint_parameters_new",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS, // return FridaEndpointParameters*
                ValueLayout.ADDRESS, // address
                ValueLayout.JAVA_SHORT, // port
                ValueLayout.ADDRESS, // certificate
                ValueLayout.ADDRESS, // origin
                ValueLayout.ADDRESS, // auth_service
                ValueLayout.ADDRESS)); // asset_root
    FRIDA_ENDPOINT_PARAMETERS_GET_ADDRESS =
        FridaLibraryLoader.findFunction(
            "frida_endpoint_parameters_get_address",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_ENDPOINT_PARAMETERS_GET_PORT =
        FridaLibraryLoader.findFunction(
            "frida_endpoint_parameters_get_port",
            FunctionDescriptor.of(ValueLayout.JAVA_SHORT, ValueLayout.ADDRESS));
    FRIDA_ENDPOINT_PARAMETERS_GET_CERTIFICATE =
        FridaLibraryLoader.findFunction(
            "frida_endpoint_parameters_get_certificate",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_ENDPOINT_PARAMETERS_GET_ORIGIN =
        FridaLibraryLoader.findFunction(
            "frida_endpoint_parameters_get_origin",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_ENDPOINT_PARAMETERS_GET_AUTH_SERVICE =
        FridaLibraryLoader.findFunction(
            "frida_endpoint_parameters_get_auth_service",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_ENDPOINT_PARAMETERS_GET_ASSET_ROOT =
        FridaLibraryLoader.findFunction(
            "frida_endpoint_parameters_get_asset_root",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_ENDPOINT_PARAMETERS_SET_ASSET_ROOT =
        FridaLibraryLoader.findFunction(
            "frida_endpoint_parameters_set_asset_root",
            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    FRIDA_STATIC_AUTHENTICATION_SERVICE_NEW =
        FridaLibraryLoader.findFunction(
            "frida_static_authentication_service_new",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    G_TLS_CERTIFICATE_NEW_FROM_FILE =
        FridaLibraryLoader.findFunction(
            "g_tls_certificate_new_from_file",
            FunctionDescriptor.of(
                ValueLayout.ADDRESS, // return GTlsCertificate*
                ValueLayout.ADDRESS, // path
                ValueLayout.ADDRESS)); // GError**
    G_FILE_NEW_FOR_PATH =
        FridaLibraryLoader.findFunction(
            "g_file_new_for_path", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    G_FILE_GET_PATH =
        FridaLibraryLoader.findFunction(
            "g_file_get_path", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
  }

  /**
   * Builder for creating EndpointParameters with optional configuration.
   *
   * <p>Usage:
   *
   * <pre>{@code
   * EndpointParameters params = EndpointParameters.builder()
   *     .address("127.0.0.1")
   *     .port(8080)
   *     .certificatePath("/path/to/cert.pem")
   *     .origin("https://example.com")
   *     .token("secret-token")
   *     .assetRoot("/path/to/assets")
   *     .build();
   * }</pre>
   */
  public static final class Builder {
    private String address;
    private int port;
    private String certificatePath;
    private String origin;
    private String token;
    private Function<String, String> authenticationCallback;
    private String assetRoot;

    private Builder() {}

    /**
     * Sets the address for the endpoint.
     *
     * @param address The network address (required)
     */
    public Builder address(final String address) {
      this.address = Objects.requireNonNull(address, "address");
      return this;
    }

    /**
     * Sets the port for the endpoint.
     *
     * @param port The port number (0-65535)
     */
    public Builder port(final int port) {
      if (port < 0 || port > 65535) {
        throw new IllegalArgumentException("Port must be between 0 and 65535");
      }
      this.port = port;
      return this;
    }

    /**
     * Sets the TLS certificate path.
     *
     * @param certificatePath Path to PEM certificate file
     */
    public Builder certificatePath(final String certificatePath) {
      this.certificatePath = certificatePath;
      return this;
    }

    /**
     * Sets the origin for CORS.
     *
     * @param origin Origin string for cross-origin restrictions
     */
    public Builder origin(final String origin) {
      this.origin = origin;
      return this;
    }

    /**
     * Sets a static authentication token.
     *
     * <p>If both token and authenticationCallback are set, the token takes precedence.
     *
     * @param token Static authentication token
     */
    public Builder token(final String token) {
      this.token = token;
      return this;
    }

    /**
     * Sets an authentication callback function.
     *
     * <p>The callback receives a token string and should return a non-empty session info string if
     * authenticated, or empty/null if authentication fails.
     *
     * <p>If both token and authenticationCallback are set, the static token takes precedence.
     *
     * @param authenticationCallback Function to validate authentication tokens
     */
    public Builder authenticationCallback(final Function<String, String> authenticationCallback) {
      this.authenticationCallback = authenticationCallback;
      return this;
    }

    /**
     * Sets the asset root directory.
     *
     * @param assetRoot Path to directory containing static assets to serve
     */
    public Builder assetRoot(final String assetRoot) {
      this.assetRoot = assetRoot;
      return this;
    }

    /** Creates the EndpointParameters from builder configuration. */
    public EndpointParameters build() {
      if (address == null || address.isEmpty()) {
        throw new IllegalArgumentException("address is required");
      }
      return new EndpointParameters(this);
    }
  }

  /** Creates a new builder for EndpointParameters. */
  public static Builder builder() {
    return new Builder();
  }

  private EndpointParameters(final Builder builder) {
    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment addressPtr = arena.allocateFrom(builder.address);
      final MemorySegment certificatePtr = loadCertificateIfNeeded(builder.certificatePath, arena);
      final MemorySegment originPtr =
          builder.origin != null ? arena.allocateFrom(builder.origin) : MemorySegment.NULL;
      final MemorySegment authServicePtr =
          createAuthenticationServiceIfNeeded(builder.token, builder.authenticationCallback, arena);
      final MemorySegment assetRootPtr = createAssetRootIfNeeded(builder.assetRoot, arena);

      this.paramsPtr =
          (MemorySegment)
              FRIDA_ENDPOINT_PARAMETERS_NEW.invokeExact(
                  addressPtr,
                  (short) builder.port,
                  certificatePtr,
                  originPtr,
                  authServicePtr,
                  assetRootPtr);

      if (paramsPtr.address() == 0) {
        throw new FridaException("Failed to create EndpointParameters");
      }
      log.debug("EndpointParameters created");
    } catch (Throwable t) {
      log.debug("Failed to create EndpointParameters", t);
      throw new FridaException("Failed to create EndpointParameters", t);
    }
  }

  /**
   * Internal constructor from native pointer.
   *
   * @param ptr Native FridaEndpointParameters pointer
   */
  EndpointParameters(final MemorySegment ptr) {
    this.paramsPtr = FridaNativeUtils.requireValidPointer(ptr, "EndpointParameters pointer");
    log.debug("EndpointParameters created from pointer");
  }

  private MemorySegment loadCertificateIfNeeded(final String certificatePath, final Arena arena)
      throws Throwable {
    if (certificatePath == null || certificatePath.isEmpty()) {
      return MemorySegment.NULL;
    }

    // Validate certificate file exists
    Path certPath = Path.of(certificatePath);
    if (!Files.exists(certPath)) {
      throw new FridaException("Certificate file not found: " + certificatePath);
    }

    final MemorySegment pathPtr = arena.allocateFrom(certificatePath);
    final MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
    final MemorySegment certPtr =
        (MemorySegment) G_TLS_CERTIFICATE_NEW_FROM_FILE.invokeExact(pathPtr, errorPtr);

    final MemorySegment error = errorPtr.get(ValueLayout.ADDRESS, 0);
    if (error.address() != 0) {
      throw new FridaException("Failed to load certificate from " + certificatePath);
    }

    if (certPtr.address() == 0) {
      throw new FridaException("Failed to load certificate from " + certificatePath);
    }

    return certPtr;
  }

  private MemorySegment createAuthenticationServiceIfNeeded(
      final String token, final Function<String, String> authCallback, final Arena arena) {
    if (token != null && !token.isEmpty()) {
      try {
        final MemorySegment tokenPtr = arena.allocateFrom(token);
        final MemorySegment authServicePtr =
            (MemorySegment) FRIDA_STATIC_AUTHENTICATION_SERVICE_NEW.invokeExact(tokenPtr);
        return FridaNativeUtils.requireValidPointer(
            authServicePtr, "Static authentication service pointer");
      } catch (NullPointerException | IllegalArgumentException | AssertionError e) {
        throw e;
      } catch (Throwable t) {
        throw new FridaException("Failed to create static authentication service", t);
      }
    }

    if (authCallback != null) {
      throw new FridaException(
          "Authentication callback services are not supported by this Java binding yet. "
              + "Use token-based authentication for now.");
    }

    return MemorySegment.NULL;
  }

  private MemorySegment createAssetRootIfNeeded(final String assetRoot, final Arena arena)
      throws Throwable {
    if (assetRoot == null || assetRoot.isEmpty()) {
      return MemorySegment.NULL;
    }

    // Validate asset root exists
    Path assetPath = Path.of(assetRoot);
    if (!Files.exists(assetPath)) {
      throw new FridaException("Asset root directory not found: " + assetRoot);
    }
    if (!Files.isDirectory(assetPath)) {
      throw new FridaException("Asset root is not a directory: " + assetRoot);
    }

    final MemorySegment pathPtr = arena.allocateFrom(assetRoot);
    return (MemorySegment) G_FILE_NEW_FOR_PATH.invokeExact(pathPtr);
  }

  /**
   * Returns the network address of this endpoint.
   *
   * @return The address string
   */
  public String getAddress() {
    try {
      MemorySegment addressPtr =
          (MemorySegment) FRIDA_ENDPOINT_PARAMETERS_GET_ADDRESS.invokeExact(paramsPtr);
      return addressPtr.reinterpret(Long.MAX_VALUE).getString(0);
    } catch (Throwable t) {
      log.debug("Failed to get address from EndpointParameters", t);
      throw new FridaException("Failed to get address from EndpointParameters", t);
    }
  }

  /**
   * Returns the port number of this endpoint.
   *
   * @return The port number
   */
  public int getPort() {
    try {
      return (short) FRIDA_ENDPOINT_PARAMETERS_GET_PORT.invokeExact(paramsPtr) & 0xFFFF;
    } catch (Throwable t) {
      log.debug("Failed to get port from EndpointParameters", t);
      throw new FridaException("Failed to get port from EndpointParameters", t);
    }
  }

  /**
   * Returns the TLS certificate for this endpoint, if configured.
   *
   * @return Certificate instance or null if no certificate is set
   */
  public Certificate getCertificate() {
    try {
      MemorySegment certPtr =
          (MemorySegment) FRIDA_ENDPOINT_PARAMETERS_GET_CERTIFICATE.invokeExact(paramsPtr);
      if (certPtr.address() == 0) {
        return null;
      }
      return new Certificate(certPtr);
    } catch (Throwable t) {
      log.debug("Failed to get certificate from EndpointParameters", t);
      throw new FridaException("Failed to get certificate from EndpointParameters", t);
    }
  }

  /**
   * Returns the origin restriction for this endpoint, if configured.
   *
   * @return Origin string or null if not set
   */
  public String getOrigin() {
    try {
      MemorySegment originPtr =
          (MemorySegment) FRIDA_ENDPOINT_PARAMETERS_GET_ORIGIN.invokeExact(paramsPtr);
      if (originPtr.address() == 0) {
        return null;
      }
      return originPtr.reinterpret(Long.MAX_VALUE).getString(0);
    } catch (Throwable t) {
      log.debug("Failed to get origin from EndpointParameters", t);
      throw new FridaException("Failed to get origin from EndpointParameters", t);
    }
  }

  /**
   * Returns the asset root directory path, if configured.
   *
   * @return Asset root path or null if not set
   */
  public String getAssetRoot() {
    try {
      MemorySegment assetRootPtr =
          (MemorySegment) FRIDA_ENDPOINT_PARAMETERS_GET_ASSET_ROOT.invokeExact(paramsPtr);
      if (assetRootPtr.address() == 0) {
        return null;
      }
      MemorySegment pathPtr = (MemorySegment) G_FILE_GET_PATH.invokeExact(assetRootPtr);
      return FridaNativeUtils.memorySegmentToStringAndFree(pathPtr);
    } catch (Throwable t) {
      log.debug("Failed to get asset root from EndpointParameters", t);
      throw new FridaException("Failed to get asset root from EndpointParameters", t);
    }
  }

  /**
   * Sets the asset root directory.
   *
   * @param assetRoot Path to directory containing static assets to serve
   */
  public void setAssetRoot(final String assetRoot) {
    if (assetRoot == null || assetRoot.isEmpty()) {
      throw new IllegalArgumentException("assetRoot cannot be null or empty");
    }

    Path assetPath = Path.of(assetRoot);
    if (!Files.exists(assetPath)) {
      throw new FridaException("Asset root directory not found: " + assetRoot);
    }
    if (!Files.isDirectory(assetPath)) {
      throw new FridaException("Asset root is not a directory: " + assetRoot);
    }

    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment pathPtr = arena.allocateFrom(assetRoot);
      final MemorySegment gFilePtr = (MemorySegment) G_FILE_NEW_FOR_PATH.invokeExact(pathPtr);
      FRIDA_ENDPOINT_PARAMETERS_SET_ASSET_ROOT.invokeExact(paramsPtr, gFilePtr);
    } catch (Throwable t) {
      log.debug("Failed to set asset root for EndpointParameters", t);
      throw new FridaException("Failed to set asset root for EndpointParameters", t);
    }
  }

  /**
   * Get the native pointer (internal use only).
   *
   * @return Native FridaEndpointParameters pointer
   */
  MemorySegment getPointer() {
    return paramsPtr;
  }

  /** Cleans resources held by the endpoint parameters. */
  public void clean() {
    FridaNativeUtils.fridaUnref(paramsPtr);
  }

  @Override
  public String toString() {
    return String.format("<EndpointParameters: %s:%d>", getAddress(), getPort());
  }
}
