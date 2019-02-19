package eu.ngpaas.pmLib;

/**
 * Represents the state of a policy
 */
public enum PolicyState {

    /**
     * A policy that has just been pushed to the policy framework
     */
    NEW("NEW", "new"),

    /**
     * A policy that succeeded in the formal validation
     */
    FORMALLY_VALIDATED("FORMALLY_VALIDATED", "FORMALLYVALIDATED"),

    /**
     * A policy that succeeded both in the formal and context validations
     */
    CONTEXT_VALIDATED("CONTEXT_VALIDATED", "CONTEXTVALIDATED"),

    /**
     * A policy that succeeded in the formal, context and conflict validations
     * and is enforced in the underlying network
     */
    ENFORCED("ENFORCED", "enforced"),

    /**
     * A policy that failed either in the context or conflict validations, or that
     * has been manually deactivated
     */
    PENDING("PENDING", "pending");

    private final String commonName;
    private final String alternativeName;

    PolicyState(String commonName, String alternativeName) {
        this.commonName = commonName;
        this.alternativeName = alternativeName;
    }


    public String getCommonName() {
        return commonName;
    }

    public String getAlternativeName() {
        return this.alternativeName;
    }

    public static PolicyState fromString(String state) {

        for(PolicyState s : values())
            if(s.getCommonName().equalsIgnoreCase(state) ||
                    s.getAlternativeName().equalsIgnoreCase(state))
                return s;

        throw new IllegalArgumentException();
    }


}