package eu.ngpaas.pmLib;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Represents a policy condition.
 */
public class PolicyCondition implements Comparable<PolicyCondition>{
    private final Logger log = LoggerFactory.getLogger(getClass());

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
     * Compares the PolicyConditions by PolicyVariable. If they are the same,
     * they are compared by PolicyValue.
     */
    @Override
    public int compareTo(PolicyCondition policyCondition) {
        if (this.getPolicyVariable().equals(policyCondition.getPolicyVariable())) {
            return this.getPolicyValue().compareTo(policyCondition.getPolicyValue());
        }
        else{
            return this.getPolicyVariable().compareTo(policyCondition.getPolicyVariable());
        }
    }

    /**
     * Two PolicyConditions are equal if they have the same PolicyVariable and PolicyAction
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PolicyCondition that = (PolicyCondition) o;
        return Objects.equals(policyValue, that.policyValue) &&
                Objects.equals(policyVariable, that.policyVariable);
    }
}

