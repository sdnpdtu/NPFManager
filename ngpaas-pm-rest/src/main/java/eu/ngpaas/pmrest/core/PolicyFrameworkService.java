package eu.ngpaas.pmrest.core;

import eu.ngpaas.pmLib.PolicyRule;
import eu.ngpaas.pmLib.PolicyRules;
import eu.ngpaas.pmLib.PolicyState;
import eu.ngpaas.pmLib.SimpleResponse;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Service;
import java.util.List;

/**
 * Represents the requirements of a Policy Framework to manage policies
 */
@Component(immediate = true)
@Service
public interface PolicyFrameworkService {

    /**
     * Deserializes a policy rule.
     * @param json the policy rule in JSON format
     * @return a PolicyRules object
     */
    PolicyRules parsePolicyRules(String json);

    /**
     * Returns the list of policies.
     * @return all policies
     */
    PolicyRules getAllPolicies();
    
    /**
     * Returns the list of active policies
     * @return active policies
     */
    PolicyRules getActivePolicies();
    
    /**
     * Returns the policy with the given id.
     * @param id the policy identifier
     * @return a policy rule
     */
    PolicyRule getPolicyById(int id);

    /**
     * Returns the policies in the given PolicyState.
     * @param policyState the policy state
     * @return policies in given state
     */
    PolicyRules getPoliciesByState(PolicyState policyState);

    /**
     * Returns the policies of the given policy type.
     * @param policyType the type of policy
     * @return policies of given type
     */
    PolicyRules getPoliciesByType(String policyType);

    /**
     * Returns the number of policies
     * @return the number of policies
     */
    int getNumberOfPolicies();

    /**
     * Activates the policy with the given id.
     * @param id the policy identifier
     * @return a SimpleResponse object containing a success/fail message.
     */
    SimpleResponse activatePolicyById(int id);

    /**
     * Deactivates the policy with the given id.
     * @param id the policy identifier
     * @return a SimpleResponse oject containing a success/fail message.
     */
    SimpleResponse deactivatePolicyById(int id);

    /**
     * Deletes the policy with the given id.
     * @param id the policy identifier
     * @return a SimpleResponse object containing a success/fail message.
     */
    SimpleResponse deletePolicyById(int id);

    /**
     * Deletes all policies
     */
    void deleteAllPolicyRules();

    /**
     * Pushes policies to the framework. This will perform the formal, context and
     * conflict validations. Por the policies that succeed, the corresponding
     * flow rules will be enforced in the underlying network.
     * @param policies list of policy rules
     * @return a SimpleResponse object containing a success/fail message.
     */
    SimpleResponse pushPolicies(PolicyRules policies);

    /**
     * Changes the priority of a policy
     * @param id the id of the policy to change the priority
     * @param newPriority the new priority for the policy
     * @return a SimpleResponse object containing a success/fail message.
     */
    SimpleResponse changePolicyPriority(int id, int newPriority);

    /**
     * Preprocesses a policy rule. Sets the policy state to NEW and converts the
     * policy conditions to DNF.
     * @param pr the policy rule to preprocess
     */
    void preprocess(PolicyRule pr);

    /**
     * Registers a policy type
     * @param policyType name of the new policy type
     * @return a SimpleResponse object containing a success/fail message.
     */
    SimpleResponse addPolicyType(String policyType);

    /**
     * Deregisters a policy type
     * @param policyType name of the policy type
     * @return a SimpleResponse object containing a success/fail message.
     */
    SimpleResponse removePolicyType(String policyType);

    /**
     * Lists the available policy types
     * @return a list of strings containing the policy types
     */
    List<String> getPolicyTypes();

}
