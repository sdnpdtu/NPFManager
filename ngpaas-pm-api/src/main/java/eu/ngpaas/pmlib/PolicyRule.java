package eu.ngpaas.pmlib;

import java.util.Collections;
import java.util.concurrent.CopyOnWriteArrayList;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Holds the structure of a policyRule.
 * Structure is based on a subset of the Policy Core Information Model
 * Form: Can be either CNF or DNF
 * Type: The type of policy (e.g. bandwidth)
 * Priority: The priority of the policy, used to resolve conflicts.
 * PolicyConditions: The set of conditions (variables and values) that must be met for the policy to pass context
 * validation.
 * PolicyActions: The set of actions (variables and values) that will be applied if the policy is to be enforced in
 * the network.
 * PolicyState: The state of the policy in its lifecycle.
 */
public class PolicyRule implements Comparable<PolicyRule> {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private int priority = 0;
    private int id = 0;
    @JsonProperty("conditions")
    private CopyOnWriteArrayList<CopyOnWriteArrayList<PolicyCondition>> policyConditions = new CopyOnWriteArrayList<>();

    @JsonProperty("actions")
    private CopyOnWriteArrayList<PolicyAction> policyActions = new CopyOnWriteArrayList<>();
    private String form;
    private String type;
    private PolicyState state;

    @JsonIgnore
    private Boolean deactivated = false;

    public PolicyRule() {
    }

    private static void cnf2dnf(CopyOnWriteArrayList<CopyOnWriteArrayList<PolicyCondition>> cnf,
                                CopyOnWriteArrayList<CopyOnWriteArrayList<PolicyCondition>> dnf,
                                CopyOnWriteArrayList<PolicyCondition> current_clause, int j) {
        if (j == cnf.size()) {
            dnf.add(current_clause);
        } else {
            for (int i = 0; i < cnf.get(j).size(); i++) {
                CopyOnWriteArrayList<PolicyCondition> new_current_clause =
                    (CopyOnWriteArrayList<PolicyCondition>) current_clause.clone();
                new_current_clause.add(cnf.get(j).get(i));
                cnf2dnf(cnf, dnf, new_current_clause, j + 1);
            }
        }
    }

    /**
     * Returns the id of the policy
     *
     * @return id
     */
    public int getId() {
        return id;
    }

    /**
     * Sets the id of the policy
     *
     * @param id id
     */
    public void setId(int id) {
        this.id = id;
    }

    /**
     * Returns the form (CNF or DNF) of the policy
     *
     * @return form
     */
    public String getForm() {
        return form;
    }

    /**
     * Sets the form of the policy
     *
     * @param form form
     */
    public void setForm(String form) {
        this.form = form;
    }

    /**
     * Returns the state of the policy
     *
     * @return state
     */
    public PolicyState getState() {
        return state;
    }

    /**
     * Sets the state of the policy
     *
     * @param state state
     */
    public void setState(PolicyState state) {
        this.state = state;
    }

    /**
     * Returns the type of the policy
     *
     * @return type
     */
    public String getType() {
        return this.type;
    }

    /**
     * Sets the type of the policy
     *
     * @param type type
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * Returns the priority of the policy
     *
     * @return priority
     */
    public int getPriority() {
        return this.priority;
    }

    /**
     * Sets the priority of the policy
     *
     * @param priority priority
     */
    public void setPriority(int priority) {
        this.priority = priority;
    }

    /**
     * Returns whether the policy is manually deactivated or not
     *
     * @return true or false
     */
    public Boolean isDeactivated() {
        return deactivated;
    }

    /**
     * Tags and untags a policy as manually deactivated. If true, it avoids the
     * policy being activated when it is in Pending state
     *
     * @param deactivated priority
     */
    public void setDeactivated(Boolean deactivated) {
        this.deactivated = deactivated;
    }

    /**
     * Returns the policy conditions
     *
     * @return policy conditions
     */
    public CopyOnWriteArrayList<CopyOnWriteArrayList<PolicyCondition>> getPolicyConditions() {
        return this.policyConditions;
    }

    /**
     * Sets the policy conditions
     *
     * @param policyConditions policy conditions
     */
    public void setPolicyConditions(CopyOnWriteArrayList<CopyOnWriteArrayList<PolicyCondition>> policyConditions) {
        this.policyConditions = policyConditions;
    }

    /**
     * Returns the policy actions
     *
     * @return policy actions
     */
    public CopyOnWriteArrayList<PolicyAction> getPolicyActions() {
        return policyActions;
    }

    /**
     * Sets the policy actions
     *
     * @param policyConditions policy actions
     */
    public void setPolicyActions(CopyOnWriteArrayList<PolicyAction> policyActions) {
        this.policyActions = policyActions;
    }

    /**
     * Adds a policy action
     *
     * @param policyAction policy action
     */
    public void addPolicyAction(PolicyAction policyAction) {
        this.policyActions.add(policyAction);
    }

    @Override
    public int compareTo(PolicyRule pr) {
        return pr.getPriority() - this.getPriority();
    }

    @Override
    public boolean equals(Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        PolicyRule that = (PolicyRule) o;

        /* Two policies are equal if they have the same type, conditions,
           actions and priority */
        return this.getType().equals(that.getType()) && this.equalPolicyConditions(that)
               && this.equalPolicyActions(that) && (this.getPriority() == that.getPriority());
    }

    /**
     * Converts the policy conditions in cnf to dnf
     *
     * @param cnf conditions in cnf
     * @return the conditions in dnf
     */
    public CopyOnWriteArrayList<CopyOnWriteArrayList<PolicyCondition>> cnf2dnf(
        CopyOnWriteArrayList<CopyOnWriteArrayList<PolicyCondition>> cnf) {
        CopyOnWriteArrayList<CopyOnWriteArrayList<PolicyCondition>> dnf = new CopyOnWriteArrayList<>();
        CopyOnWriteArrayList<PolicyCondition> current_clause = new CopyOnWriteArrayList<>();
        int j = 0;
        cnf2dnf(cnf, dnf, current_clause, j);
        return dnf;

    }

    /**
     * Sorts the condition s of a policy
     */
    public void sortConditions() {
        // Sort each clause individually
        CopyOnWriteArrayList<CopyOnWriteArrayList<PolicyCondition>> pcs = this.getPolicyConditions();
        for (CopyOnWriteArrayList<PolicyCondition> clause : pcs) {
            Collections.sort(pcs.get(pcs.indexOf(clause)));
        }

        // Sort clauses
        for (int i = 0; i < pcs.size() - 1; i++) {
            for (int j = 0; j < pcs.size() - i - 1; j++) {

                if (pcs.get(j).get(0).compareTo(pcs.get(j + 1).get(0)) > 0) {
                    CopyOnWriteArrayList<PolicyCondition> tmp = pcs.get(j);
                    pcs.set(j, pcs.get(j + 1));
                    pcs.set(j + 1, tmp);
                }
            }
        }
    }

    /**
     * Checks if the conditions of a policy are equal to the conditions of
     * another policy.
     *
     * @param pr the policy rule to compare
     * @return true or false
     */
    public Boolean equalPolicyConditions(PolicyRule pr) {
        if (this.getPolicyConditions().size() != pr.getPolicyConditions().size()) {
            return false;
        }

        this.sortConditions();

        int i = 0;
        for (CopyOnWriteArrayList<PolicyCondition> clause : this.getPolicyConditions()) {
            if (clause.size() != pr.getPolicyConditions().get(i).size()) {
                return false;
            }
            for (int j = 0; j < clause.size(); j++) {
                if (!this.getPolicyConditions().get(i).get(j)
                         .equals(pr.getPolicyConditions().get(i).get(j))) {
                    return false;
                }
            }
            i++;
        }
        return true;
    }

    /**
     * Checks if the actions of a policy are equal to the actions of
     * another policy.
     *
     * @param pr the policy rule to compare
     * @return true or false
     */
    public Boolean equalPolicyActions(PolicyRule pr) {
        Collections.sort(pr.getPolicyActions());

        int i = 0;
        for (PolicyAction pa : this.getPolicyActions()) {
            if (!pa.equals(pr.getPolicyActions().get(i))) {
                return false;
            }
            i++;
        }
        return true;
    }


    /**
     * Parses a PolicyRule object to JSON
     *
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

}
