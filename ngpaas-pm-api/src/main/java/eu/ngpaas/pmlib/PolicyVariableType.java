package eu.ngpaas.pmlib;

/**
 * Represents the types of policy variables for the Policy Conditions
 * and the Policy Actions
 */
public enum PolicyVariableType {
    /**
     * An IPv4 address (e.g. 10.0.0.1)
     */
    IPV4,

    /*
     * A MAC address (e.g. 00:11:22:33:44:55)
     */
    MAC,

    /*
     * A Port number (e.g. 80)
     */
    PORT
}
