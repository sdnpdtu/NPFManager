package eu.ngpaas.pmLib;

import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Service;

/**
 * Represents the contract to be implemented by each policy type
 */
@Component(immediate = true)
@Service
public interface PolicyService {
	
	/**
	 * Analyzes the structure of a policy rule
	 * @param pr a policy rule
	 * @return a SimpleResponse object with a success/fail message
	 */
    SimpleResponse formalValidation(PolicyRule pr);

    /**
	 * Checks if the network can accomodate the policy
	 * @param pr a policy rule
	 * @return a SimpleResponse object with a success/fail message
	 */
    SimpleResponse contextValidation(PolicyRule pr);

    /**
	 * Returns the flow rules that would be installed in the switches if the
	 * policy is enforced.
	 * @param pr a policy rule
	 * @return a ForwardingObjectiveList with the list of flow rules and the
	 * devices
	 */
    ForwardingObjectiveList getFlowRules(PolicyRule pr);

    /**
     * Enforces a policy rule in the underlying network
     * @param pr a policy rule
     */
    void enforce(PolicyRule pr);

    /**
     * Removes a policy rule from the underlying network
     * @param pr a policy rule
     */
    void remove(PolicyRule pr);
}
