package eu.ngpaas.pmlib;

import java.util.Collections;
import java.util.HashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Helper class with useful methods to formally validate a policy
 */
public class PolicyHelper {

    /**
     * Deserializes a JSON string  into a policy rule
     *
     * @param body JSON string
     * @return parsed PolicyRule
     */
    public static PolicyRule parsePolicyRule(String body) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        PolicyRule policyRule = null;
        try {
            policyRule = mapper.readValue(body, PolicyRule.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return policyRule;
    }

    /**
     * Validates the PolicyVariables of a policy rule
     *
     * @param pr                   a policy rule
     * @param validCondVariables   the supported condition variables
     * @param validActionVariables the supported action variables
     * @return a SimpleResponse object with the success/fail message
     */
    public static SimpleResponse validateVariables(PolicyRule pr,
                                                   CopyOnWriteArrayList<String> validCondVariables,
                                                   CopyOnWriteArrayList<String> validActionVariables) {

        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()) {
            for (PolicyCondition pc : clause) {
                if (!validCondVariables.contains(pc.getPolicyVariable())) {
                    return new SimpleResponse("Formal error: '" +
                                              pc.getPolicyVariable() + "' is not a valid condition variable.", false);
                }
            }
        }
        for (PolicyAction pa : pr.getPolicyActions()) {
            if (!validActionVariables.contains(pa.getPolicyVariable())) {
                return new SimpleResponse("Formal error: '" + pa.getPolicyVariable() +
                                          "' is not a valid action variable.", false);
            }
        }
        return new SimpleResponse("All conditions variables are valid", true);
    }

    /**
     * Validates the value of a PolicyCondition
     *
     * @param pr       a policy rule
     * @param variable the variable of the condition
     * @param type     the type of variable (IP, MAC, Port, etc.)
     * @return a SimpleResponse object with the success/fail message
     */
    public static SimpleResponse validateConditionValue(PolicyRule pr,
                                                        String variable, PolicyVariableType type) {

        Boolean isValidType;
        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()) {
            for (PolicyCondition pc : clause) {
                if (pc.getPolicyVariable().equalsIgnoreCase(variable)) {
                    switch (type) {
                        case IPV4:
                            isValidType = isIPV4address(pc.getPolicyValue());
                            break;
                        case MAC:
                            isValidType = isMACaddress(pc.getPolicyValue());
                            break;
                        case PORT:
                            isValidType = isPort(pc.getPolicyValue());
                            break;
                        default:
                            return new SimpleResponse("Invalid PolicyVariableType provided", false);
                    }
                    if (!isValidType) {
                        return new SimpleResponse("Policy Condition value '" + pc.getPolicyValue() +
                                                  "' does not have a valid format.", false);
                    }
                }
            }
        }
        return new SimpleResponse("Valid condition value", true);
    }

    /**
     * Checks if a string has a valid IPv4 format.
     *
     * @param value the string
     * @return true or false
     */
    private static Boolean isIPV4address(String value) {
        Pattern p = Pattern.compile("^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
        return p.matcher(value).matches();
    }

    /**
     * Checks if a string has a valid MAC format.
     *
     * @param value the string
     * @return true or false
     */
    private static Boolean isMACaddress(String value) {
        Pattern p = Pattern.compile("^([a-fA-F0-9]{2}[:-]){5}[a-fA-F0-9]{2}$");
        return p.matcher(value).matches();
    }

    /**
     * Checks if a string has a valid Port format.
     *
     * @param value the string
     * @return true or false
     */
    private static Boolean isPort(String value) {
        try {
            return Integer.parseInt(value) < 65536;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Validates the value of a PolicyCondition
     *
     * @param pr          a policy rule
     * @param variable    the variable of the condition
     * @param validValues the set of valid values the variable can take
     * @return a SimpleResponse object with the success/fail message
     */
    public static SimpleResponse validateConditionValue(PolicyRule pr,
                                                        String variable, CopyOnWriteArrayList<String> validValues) {
        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()) {
            for (PolicyCondition pc : clause) {
                if (pc.getPolicyVariable().equalsIgnoreCase(variable) &&
                    !validValues.contains(pc.getPolicyValue())) {
                    return new SimpleResponse("Policy Variable '" +
                                              pc.getPolicyVariable() + "' does not have a valid value.", false);
                }
            }
        }
        return new SimpleResponse("Valid condition value", true);
    }

    /**
     * Validates the value of a PolicyAction
     *
     * @param pr       a policy rule
     * @param variable the variable of the action
     * @param type     the type of variable
     * @return a SimpleResponse object with the success/fail message
     */
    public static SimpleResponse validateActionValue(PolicyRule pr,
                                                     String variable, PolicyVariableType type) {

        Boolean isValidType;
        for (PolicyAction pa : pr.getPolicyActions()) {
            if (pa.getPolicyVariable().equalsIgnoreCase(variable)) {
                switch (type) {
                    case IPV4:
                        isValidType = isIPV4address(pa.getPolicyValue());
                        break;
                    case MAC:
                        isValidType = isMACaddress(pa.getPolicyValue());
                        break;
                    case PORT:
                        isValidType = isPort(pa.getPolicyValue());
                        break;
                    default:
                        return new SimpleResponse("Invalid PolicyVariableType provided", false);
                }
                if (!isValidType) {
                    return new SimpleResponse("Policy Action value '" +
                                              pa.getPolicyValue() + "' does not have a valid format.",
                                              false);
                }
            }
        }

        return new SimpleResponse("Valid action value", true);
    }

    /**
     * Validates the value of a PolicyAction
     *
     * @param pr          a policy rule
     * @param variable    the variable of the action
     * @param validValues the set of valid values the variable can take
     * @return a SimpleResponse object with the success/fail message
     */
    public static SimpleResponse validateActionValue(PolicyRule pr,
                                                     String variable, CopyOnWriteArrayList<String> validValues) {
        for (PolicyAction pa : pr.getPolicyActions()) {
            if (pa.getPolicyVariable().equalsIgnoreCase(variable) &&
                !validValues.contains(pa.getPolicyValue())) {
                return new SimpleResponse("Policy Variable '"
                                          + pa.getPolicyVariable() + "' does not have a valid value.", false);
            }
        }
        return new SimpleResponse("Valid action value", true);
    }

    /**
     * Validates that the relations between conditions are valid.
     *
     * @param pr                 a policy rule
     * @param mustCoexistDict    a dictionary that specifies which conditions must be
     *                           specified together (assumes the conditions are in DNF form)
     * @param mustNotCoexistDict a dictionary that specifies which conditions
     *                           cannot be specified at the same time
     * @return a SimpleResponse object with the success/fail message
     */
    public static SimpleResponse validateConditionVariableRelations(PolicyRule pr,
                                                                    HashMap<String,
                                                                        CopyOnWriteArrayList<CopyOnWriteArrayList<String>>> mustCoexistDict,
                                                                    HashMap<String, CopyOnWriteArrayList<String>>
                                                                        mustNotCoexistDict) {

        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()) {
            for (PolicyCondition pc : clause) {
                try {
                    CopyOnWriteArrayList<CopyOnWriteArrayList<String>> requiredConds =
                        mustCoexistDict.get(pc.getPolicyVariable());
                    int count = 0;
                    for (CopyOnWriteArrayList<String> requiredClause : requiredConds) {
                        if (clause.containsAll(requiredClause)) {
                            break;
                        } else {
                            count++;
                        }
                    }
                    if (count == requiredConds.size()) {
                        return new SimpleResponse("Not all the condition relations of the policy condition '" +
                                                  pc.getPolicyVariable() + "' are fulfilled.", false);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                try {
                    CopyOnWriteArrayList<String> incompatibleConds = mustNotCoexistDict.get(pc.getPolicyVariable());
                    if (!Collections.disjoint(clause, incompatibleConds)) {
                        return new SimpleResponse("Some conditions are incompatible", false);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        return new SimpleResponse("Valid conditions relations", true);
    }

    /**
     * Validates that the relations between actions are valid.
     *
     * @param pr                 a policy rule
     * @param mustCoexistDict    a dictionary that specifies which actions must be
     *                           specified together
     * @param mustNotCoexistDict a dictionary that specifies which actions
     *                           cannot be specified at the same time
     * @return a SimpleResponse object with the success/fail message
     */
    public static SimpleResponse validateActionVariableRelations(PolicyRule pr,
                                                                 HashMap<String,
                                                                     CopyOnWriteArrayList<CopyOnWriteArrayList<String>>> mustCoexistDict,
                                                                 HashMap<String, CopyOnWriteArrayList<String>>
                                                                     mustNotCoexistDict) {
        CopyOnWriteArrayList<PolicyAction> pas = pr.getPolicyActions();
        for (PolicyAction pa : pas) {
            try {
                CopyOnWriteArrayList<CopyOnWriteArrayList<String>> requiredConds =
                    mustCoexistDict.get(pa.getPolicyVariable());
                int count = 0;
                for (CopyOnWriteArrayList<String> requiredClause : requiredConds) {
                    if (pas.containsAll(requiredClause)) {
                        break;
                    } else {
                        count++;
                    }
                }
                if (count == requiredConds.size()) {
                    return new SimpleResponse("Not all the action relations of the policy action '" +
                                              pa.getPolicyVariable() + "' are fulfilled.", false);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            try {
                CopyOnWriteArrayList<String> incompatibleActions = mustNotCoexistDict.get(pa.getPolicyVariable());
                if (!Collections.disjoint(pas, incompatibleActions)) {
                    return new SimpleResponse("Some actions are incompatible", false);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


        return new SimpleResponse("Valid conditions relations", true);
    }

}
