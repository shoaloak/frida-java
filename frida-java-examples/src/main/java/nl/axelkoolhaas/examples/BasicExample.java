package nl.axelkoolhaas.examples;

import nl.axelkoolhaas.Frida;

/**
 * Simple example demonstrating basic Frida Java bindings usage.
 * This example shows how to initialize Frida and get version information.
 */
public class BasicExample {

    public static void main(String[] args) {
        System.out.println("Frida Java Bindings - Basic Example");
        System.out.println("===================================");

        try {
            // Initialize Frida
            Frida.init();
            System.out.println("✓ Frida initialized successfully");

            // Get version information
            String versionString = Frida.getVersionString();
            int[] version = Frida.getVersion();
            System.out.println("Frida version: " + versionString);
            System.out.printf("Version components: %d.%d.%d.%d%n",
                version[0], version[1], version[2], version[3]);

            System.out.println("\n=== Device Enumeration ===");

            // Create device manager and enumerate devices
            manager = new FridaDeviceManager();
            FridaDevice[] devices = manager.enumerateDevices();

            System.out.println("Available devices:");
            FridaDevice localDevice = null;
            for (FridaDevice device : devices) {
                System.out.println("  - " + device.getName() + " (type: " + device.getType() + ")");
                if (device.getType() == FridaDeviceType.LOCAL) {
                    localDevice = device;
                }
            }

            if (localDevice == null) {
                System.err.println("No local device found!");
                return;
            }

            System.out.println("\n=== Process Enumeration ===");

            // Enumerate processes on the local device
            FridaProcess[] processes = localDevice.enumerateProcesses();
            System.out.println("First 10 processes on local device:");

            for (int i = 0; i < Math.min(10, processes.length); i++) {
                FridaProcess process = processes[i];
                System.out.println("  " + process.getPid() + ": " + process.getName());
            }

            // Find a target process to demonstrate attachment
            FridaProcess targetProcess = null;
            String[] candidateProcesses = {"Safari", "Chrome", "firefox", "TextEdit", "Calculator", "Finder"};

            for (String candidate : candidateProcesses) {
                for (FridaProcess process : processes) {
                    if (process.getName().toLowerCase().contains(candidate.toLowerCase())) {
                        targetProcess = process;
                        break;
                    }
                }
                if (targetProcess != null) break;
            }

            if (targetProcess != null) {
                System.out.println("\n=== Script Injection Demo ===");
                System.out.println("Found target process: " + targetProcess.getName() + " (PID: " + targetProcess.getPid() + ")");

                try {
                    // Attach to the target process
                    FridaSession session = localDevice.attach(targetProcess.getPid());

                    // Set up detach listener
                    session.setDetachListener((s, reason) -> {
                        System.out.println("Session detached. Reason: " + reason);
                    });

                    // Create script options
                    FridaScriptOptions options = new FridaScriptOptions();
                    options.setName("example-script");
                    options.setRuntime(FridaScriptRuntime.QJS);

                    // Create a simple JavaScript payload
                    String scriptSource =
                        "console.log('Hello from Frida!');\n" +
                        "console.log('Process name: ' + Process.mainModule.name);\n" +
                        "console.log('Process PID: ' + Process.id);\n" +
                        "\n" +
                        "// Hook a common function to demonstrate interception\n" +
                        "if (Process.platform === 'darwin') {\n" +
                        "  try {\n" +
                        "    var openPtr = Module.getExportByName(null, 'open');\n" +
                        "    if (openPtr) {\n" +
                        "      Interceptor.attach(openPtr, {\n" +
                        "        onEnter: function(args) {\n" +
                        "          var path = args[0].readUtf8String();\n" +
                        "          console.log('[*] open() called with path: ' + path);\n" +
                        "        }\n" +
                        "      });\n" +
                        "      console.log('Successfully hooked open() function');\n" +
                        "    }\n" +
                        "  } catch (e) {\n" +
                        "    console.log('Could not hook open(): ' + e.message);\n" +
                        "  }\n" +
                        "}\n" +
                        "\n" +
                        "// Send a custom message\n" +
                        "send({type: 'info', message: 'Script loaded successfully'});";

                    // Create and load the script
                    FridaScript script = session.createScript(scriptSource, options);

                    // Set up message listener
                    script.setMessageListener((s, message, data) -> {
                        System.out.println("Script message: " + message);
                    });

                    System.out.println("Loading script...");
                    script.load();

                    System.out.println("Script loaded! Monitoring for 3 seconds...");
                    Thread.sleep(3000);

                    // Clean up
                    script.unload();
                    session.detach();

                    System.out.println("Script unloaded and session detached.");

                } catch (FridaException e) {
                    System.err.println("Failed to attach or inject script: " + e.getMessage());
                } catch (InterruptedException e) {
                    System.err.println("Interrupted: " + e.getMessage());
                }
            } else {
                System.out.println("\n=== No Suitable Target Process Found ===");
                System.out.println("To see script injection in action, please start one of these applications:");
                for (String app : candidateProcesses) {
                    System.out.println("  - " + app);
                }
            }

>>>>>>> 629c812 (Refactor: Changed from FridaJava to Frida name)

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Clean up
            Frida.deinit();
            System.out.println("✓ Frida deinitialized");
        }
    }
}
