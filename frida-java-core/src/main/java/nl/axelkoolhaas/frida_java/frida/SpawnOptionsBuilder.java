/*
 * Copyright (C) 2026 Axel Koolhaas
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

import java.util.List;
import java.util.Map;

/**
 * Builder for creating SpawnOptions instances with a fluent API.
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * SpawnOptions options = SpawnOptions.builder()
 *     .argv("bash", "-c", "echo hello")
 *     .cwd("/tmp")
 *     .stdio(Stdio.PIPE)
 *     .build();
 * }</pre>
 */
public final class SpawnOptionsBuilder {
  private List<String> argv;
  private Map<String, String> envp;
  private Map<String, String> env;
  private String cwd;
  private Stdio stdio;

  SpawnOptionsBuilder() {}

  /**
   * Set arguments for the spawned process
   *
   * @param argv List of arguments (including program name as first argument)
   * @return this builder
   */
  public SpawnOptionsBuilder argv(List<String> argv) {
    this.argv = argv;
    return this;
  }

  /**
   * Set arguments for the spawned process
   *
   * @param argv Arguments (including program name as first argument)
   * @return this builder
   */
  public SpawnOptionsBuilder argv(String... argv) {
    this.argv = List.of(argv);
    return this;
  }

  /**
   * Set environment variables (envp format, replaces entire environment)
   *
   * @param envp Map of environment variables
   * @return this builder
   */
  public SpawnOptionsBuilder envp(Map<String, String> envp) {
    this.envp = envp;
    return this;
  }

  /**
   * Set environment variables (env format, merged with existing)
   *
   * @param env Map of environment variables
   * @return this builder
   */
  public SpawnOptionsBuilder env(Map<String, String> env) {
    this.env = env;
    return this;
  }

  /**
   * Set current working directory for the spawned process
   *
   * @param cwd Working directory path
   * @return this builder
   */
  public SpawnOptionsBuilder cwd(String cwd) {
    this.cwd = cwd;
    return this;
  }

  /**
   * Set standard I/O configuration for the spawned process
   *
   * @param stdio Standard I/O configuration
   * @return this builder
   */
  public SpawnOptionsBuilder stdio(Stdio stdio) {
    this.stdio = stdio;
    return this;
  }

  /**
   * Build the SpawnOptions instance
   *
   * @return A new SpawnOptions with the configured settings
   */
  public SpawnOptions build() {
    SpawnOptions options = new SpawnOptions();

    if (argv != null && !argv.isEmpty()) {
      options.setArgv(argv.toArray(new String[0]));
    }
    if (envp != null && !envp.isEmpty()) {
      options.setEnvp(envp);
    }
    if (env != null && !env.isEmpty()) {
      options.setEnv(env);
    }
    if (cwd != null) {
      options.setCwd(cwd);
    }
    if (stdio != null) {
      options.setStdio(stdio);
    }

    return options;
  }
}
