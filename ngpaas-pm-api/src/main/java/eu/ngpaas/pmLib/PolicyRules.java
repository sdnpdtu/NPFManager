package eu.ngpaas.pmLib;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Represents a list of PolicyRule objects
 */
public class PolicyRules {

    @JsonIgnore
    private final Logger log = LoggerFactory.getLogger(getClass());


    @JsonProperty(value = "policies", required = true)
    private CopyOnWriteArrayList<PolicyRule> policyRules;

    /**
     * Constructs a PolicyRules object with an empty list of policy rules
     */
    public PolicyRules() {
        this.policyRules = new CopyOnWriteArrayList<>();
    }

    /**
     * Returns the list of policy rules
     * @return list of policy rules
     */
    public CopyOnWriteArrayList<PolicyRule> getPolicyRules() {
        return policyRules;
    }

    /**
     * Sets the list of policy rules
     * @param policyRules list of policy rules
     */
    public void setPolicyRules(CopyOnWriteArrayList<PolicyRule> policyRules) {
        this.policyRules = policyRules;
    }

    /**
     * Adds a PolicyRule to the list of policy rules
     * @param pr a policy rule
     */
    public void addRule(PolicyRule pr) {

        this.policyRules.add(pr);

    }

    /**
     * Deletes a PolicyRule from the list of policy rules
     * @param prToDelete a policy rule
     * @return true 
     */
    public Boolean deleteRule(PolicyRule prToDelete) {
        this.policyRules.remove(prToDelete);

        return true;
    }

    /**
     * Parses a PolicyRules object to JSON
     * @return a JSON string
     */
    public String toJSONString() {

        ObjectMapper mapper = new ObjectMapper();

        String json = null;

        try {
            json = mapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {

            e.printStackTrace();
        }

        return json;
    }

    @Override
    public PolicyRules clone() {
        PolicyRules prs = new PolicyRules();
        for (PolicyRule pr : this.getPolicyRules()) {
            prs.addRule(pr);
        }
        return prs;
    }
}