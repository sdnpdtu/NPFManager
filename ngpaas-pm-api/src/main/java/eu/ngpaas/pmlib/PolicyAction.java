package eu.ngpaas.pmlib;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents a policy action
 */
public class PolicyAction implements Comparable<PolicyAction> {

    @JsonProperty("value")
    private String policyValue;

    @JsonProperty("variable")
    private String policyVariable;

    public String getPolicyValue() {
        return policyValue;
    }

    public void setPolicyValue(String policyValue) {
        this.policyValue = policyValue;
    }

    public String getPolicyVariable() {
        return policyVariable;
    }

    public void setPolicyVariable(String policyVariable) {
        this.policyVariable = policyVariable;
    }

    /**
     * Compares the PolicyActions by PolicyVariable. If they are the same,
     * they are compared by PolicyValue.
     */
    @Override
    public int compareTo(PolicyAction policyAction) {
        if (this.getPolicyVariable().equals(policyAction.getPolicyVariable())) {
            return this.getPolicyValue().compareTo(policyAction.getPolicyValue());
        } else {
            return this.getPolicyVariable().compareTo(policyAction.getPolicyVariable());
        }
    }

    /**
     * Two PolicyActions are equal if they have the same PolicyVariable and PolicyAction
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        PolicyAction that = (PolicyAction) o;
        return Objects.equals(policyValue, that.policyValue) &&
               Objects.equals(policyVariable, that.policyVariable);
    }
}

