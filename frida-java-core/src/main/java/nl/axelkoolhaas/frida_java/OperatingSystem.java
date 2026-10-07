package nl.axelkoolhaas.frida_java;

public enum OperatingSystem {
  WINDOWS("windows"),
  MACOS("macos"),
  LINUX("linux");

  private final String name;

  OperatingSystem(String name) {
    this.name = name;
  }

  public String getName() {
    return name;
  }
}
