package nl.axelkoolhaas.frida_java.frida;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.axelkoolhaas.frida_java.FridaLibraryLoader;
import nl.axelkoolhaas.frida_java.FridaNativeUtils;

/** Represents a GTlsCertificate from Frida. */
@SuppressWarnings("unused")
public final class Certificate {
  private static final Logger log = LoggerFactory.getLogger(Certificate.class);
  private final MemorySegment certPtr;

  // Native method handles
  private static final MethodHandle G_TLS_CERTIFICATE_GET_ISSUER_NAME;
  private static final MethodHandle G_TLS_CERTIFICATE_GET_SUBJECT_NAME;
  private static final MethodHandle G_TLS_CERTIFICATE_GET_NOT_VALID_BEFORE;
  private static final MethodHandle G_TLS_CERTIFICATE_GET_NOT_VALID_AFTER;
  private static final MethodHandle G_DATE_TIME_FORMAT;

  private static final String C_TIME_FORMAT = "%Y-%m-%d %H:%M:%S";
  private static final DateTimeFormatter JAVA_TIME_FORMAT =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

  static {
    Frida.ensureInitialized();
    G_TLS_CERTIFICATE_GET_ISSUER_NAME =
        FridaLibraryLoader.findFunction(
            "g_tls_certificate_get_issuer_name",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    G_TLS_CERTIFICATE_GET_SUBJECT_NAME =
        FridaLibraryLoader.findFunction(
            "g_tls_certificate_get_subject_name",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    G_TLS_CERTIFICATE_GET_NOT_VALID_BEFORE =
        FridaLibraryLoader.findFunction(
            "g_tls_certificate_get_not_valid_before",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    G_TLS_CERTIFICATE_GET_NOT_VALID_AFTER =
        FridaLibraryLoader.findFunction(
            "g_tls_certificate_get_not_valid_after",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    G_DATE_TIME_FORMAT =
        FridaLibraryLoader.findFunction(
            "g_date_time_format",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
  }

  public Certificate(final MemorySegment ptr) {
    this.certPtr = FridaNativeUtils.requireValidPointer(ptr, "Certificate pointer");
    log.debug("Certificate created");
  }

  /** Returns the issuer name for the certificate. */
  public String getIssuerName() {
    try {
      MemorySegment namePtr =
          (MemorySegment) G_TLS_CERTIFICATE_GET_ISSUER_NAME.invokeExact(certPtr);
      return FridaNativeUtils.memorySegmentToStringAndFree(namePtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError t) {
      throw t;
    } catch (Throwable t) {
      log.debug("Failed to get issuer name from Certificate", t);
      throw new FridaException("Failed to get issuer name from certificate", t);
    }
  }

  /** Returns the subject name for the certificate. */
  public String getSubjectName() {
    try {
      MemorySegment namePtr =
          (MemorySegment) G_TLS_CERTIFICATE_GET_SUBJECT_NAME.invokeExact(certPtr);
      return FridaNativeUtils.memorySegmentToStringAndFree(namePtr);
    } catch (NullPointerException | IllegalArgumentException | AssertionError t) {
      throw t;
    } catch (Throwable t) {
      log.debug("Failed to get subject name from Certificate", t);
      throw new FridaException("Failed to get subject name from certificate", t);
    }
  }

  /** Returns the time before which the certificate is not valid. */
  public LocalDateTime getNotValidBefore() {
    try {
      MemorySegment dateTimePtr =
          (MemorySegment) G_TLS_CERTIFICATE_GET_NOT_VALID_BEFORE.invokeExact(certPtr);
      try (Arena arena = Arena.ofConfined()) {
        MemorySegment formatStr = arena.allocateFrom(C_TIME_FORMAT);
        MemorySegment formattedPtr =
            (MemorySegment) G_DATE_TIME_FORMAT.invokeExact(dateTimePtr, formatStr);
        String formatted = FridaNativeUtils.memorySegmentToStringAndFree(formattedPtr);
        return LocalDateTime.parse(formatted, JAVA_TIME_FORMAT);
      }
    } catch (NullPointerException | IllegalArgumentException | AssertionError t) {
      throw t;
    } catch (Throwable t) {
      log.debug("Failed to get not valid before from Certificate", t);
      throw new FridaException("Failed to get not valid before from certificate", t);
    }
  }

  /** Returns the time after which the certificate is not valid. */
  public LocalDateTime getNotValidAfter() {
    try {
      MemorySegment dateTimePtr =
          (MemorySegment) G_TLS_CERTIFICATE_GET_NOT_VALID_AFTER.invokeExact(certPtr);
      try (Arena arena = Arena.ofConfined()) {
        MemorySegment formatStr = arena.allocateFrom(C_TIME_FORMAT);
        MemorySegment formattedPtr =
            (MemorySegment) G_DATE_TIME_FORMAT.invokeExact(dateTimePtr, formatStr);
        String formatted = FridaNativeUtils.memorySegmentToStringAndFree(formattedPtr);
        return LocalDateTime.parse(formatted, JAVA_TIME_FORMAT);
      }
    } catch (NullPointerException | IllegalArgumentException | AssertionError t) {
      throw t;
    } catch (Throwable t) {
      log.debug("Failed to get not valid after from Certificate", t);
      throw new FridaException("Failed to get not valid after from certificate", t);
    }
  }

  /**
   * Get the native pointer (internal use only)
   *
   * @return Native GTlsCertificate pointer
   */
  MemorySegment getPointer() {
    return certPtr;
  }

  /** Cleans resources held by the certificate. */
  public void clean() {
    FridaNativeUtils.fridaUnref(certPtr);
  }

  @Override
  public String toString() {
    return String.format("<Certificate>: <%s>", Objects.toIdentityString(certPtr));
  }
}
