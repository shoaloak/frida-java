package nl.axelkoolhaas;

/**
 * Information about a running process on a Frida device.
 */
public class ProcessInfo {

    private final int pid;
    private final String name;
    private final String[] parameters;

    /**
     * Constructor for ProcessInfo.
     * @param pid Process ID
     * @param name Process name/executable path
     * @param parameters Process parameters/arguments
     */
    public ProcessInfo(int pid, String name, String[] parameters) {
        this.pid = pid;
        this.name = name;
        this.parameters = parameters != null ? parameters.clone() : new String[0];
    }

    /**
     * Get the process ID.
     * @return Process ID
     */
    public int getPid() {
        return pid;
    }

    /**
     * Get the process name or executable path.
     * @return Process name
     */
    public String getName() {
        return name;
    }

    /**
     * Get the process parameters/arguments.
     * @return Array of process arguments
     */
    public String[] getParameters() {
        return parameters.clone();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ProcessInfo{pid=").append(pid);
        sb.append(", name='").append(name).append("'");
        if (parameters.length > 0) {
            sb.append(", parameters=[");
            for (int i = 0; i < parameters.length; i++) {
                if (i > 0) sb.append(", ");
                sb.append("'").append(parameters[i]).append("'");
            }
            sb.append("]");
        }
        sb.append("}");
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;

        ProcessInfo that = (ProcessInfo) obj;
        return pid == that.pid;
    }

    @Override
    public int hashCode() {
        return Integer.hashCode(pid);
    }
}
