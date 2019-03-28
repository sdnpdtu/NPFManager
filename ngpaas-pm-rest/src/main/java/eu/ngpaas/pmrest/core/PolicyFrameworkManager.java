package eu.ngpaas.pmrest.core;

import static org.slf4j.LoggerFactory.getLogger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriBuilder;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.ngpaas.pmlib.ConflictValidator;
import eu.ngpaas.pmlib.ForwardingObjectiveList;
import eu.ngpaas.pmlib.PolicyAction;
import eu.ngpaas.pmlib.PolicyCollector;
import eu.ngpaas.pmlib.PolicyCondition;
import eu.ngpaas.pmlib.PolicyRule;
import eu.ngpaas.pmlib.PolicyRules;
import eu.ngpaas.pmlib.PolicyState;
import eu.ngpaas.pmlib.SimpleResponse;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Deactivate;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.onlab.osgi.DefaultServiceDirectory;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.slf4j.Logger;

/**
 * Implements a manager of policies
 */
public class PolicyFrameworkManager implements PolicyFrameworkService {

    private final Logger log = getLogger(getClass());
    /**
     * Contains all the policies of the framework
     */
    private PolicyRules policies = null;
    /**
     * Contains the list of the supported policy types
     */
    private List<String> policyTypes = new ArrayList<>();
    private AtomicInteger uniqueId = new AtomicInteger();
    private WebTarget RESTtarget = ClientBuilder.newClient(new ClientConfig())
                                                .register(HttpAuthenticationFeature.basic("onos", "rocks"))
                                                .target(UriBuilder.fromUri("http://localhost:8181/onos").build());
    private ReentrantLock lock = new ReentrantLock();

    @Activate
    public void activate() {
        log.info("Policy Service started");
        this.policies = new PolicyRules();
    }

    @Deactivate
    public void deactivate() {
        log.info("Policy Service stopped ");
    }

    @Override
    public PolicyRules getAllPolicies() {
        return this.policies;
    }

    @Override
    public PolicyRules getActivePolicies() {
        PolicyRules apr = new PolicyRules();
        apr.setPolicyRules(this.policies.getPolicyRules()
                                        .stream()
                                        .filter(policy -> policy.getState().equals(PolicyState.ENFORCED))
                                        .collect(new PolicyCollector()));
        return apr;
    }

    @Override
    public PolicyRule getPolicyById(int id) {
        CopyOnWriteArrayList<PolicyRule> filteredPolicies = this.policies.getPolicyRules()
                                                                         .stream()
                                                                         .filter(policy -> policy.getId() == id)
                                                                         .collect(new PolicyCollector());
        if (filteredPolicies.isEmpty()) {
            return null;
        } else {
            return filteredPolicies.get(0);
        }
    }

    @Override
    public PolicyRules getPoliciesByState(PolicyState policyState) {
        PolicyRules apr = new PolicyRules();
        apr.setPolicyRules(this.policies.getPolicyRules()
                                        .stream()
                                        .filter(policy -> policy.getState().equals(policyState))
                                        .collect(new PolicyCollector()));
        return apr;
    }

    @Override
    public PolicyRules getPoliciesByType(String policyType) {
        PolicyRules apr = new PolicyRules();
        apr.setPolicyRules(this.policies.getPolicyRules()
                                        .stream()
                                        .filter(policy -> policy.getType().equals(policyType))
                                        .collect(new PolicyCollector()));
        return apr;
    }

    @Override
    public int getNumberOfPolicies() {
        return this.policies.getPolicyRules().size();
    }

    @Override
    public SimpleResponse activatePolicyById(int id) {

        /* Looks for a policy with the given id in pending state. 
        If it is not found, returns an error message */
        PolicyRule p = getPolicyById(id, getPoliciesByState(PolicyState.PENDING));
        List messages = new ArrayList();

        if (p == null) {
            return new SimpleResponse(
                "Policy [" + String.valueOf(id) + "] not in Pending state.", false);
        }

        // Untag the policy so it can be enforced as soon as possible
        p.setDeactivated(false);

        // Apply the context validation. If fails, returns an error message
        if (!contextValidation(p).isSuccess()) {
            return new SimpleResponse(
                "Policy [" + String.valueOf(p.getId()) + "] failed at context validation.", false);
        }
        try {
            lock.lock();
            /* Apply the conflict validation to the policy we try to activate. 
            If fails, returns an error messsage */
            SimpleResponse sr = conflictValidator(p, getActivePolicies());
            messages = sr.getMessages();
            if (!sr.isSuccess()) {
                messages.add("Policy [" + String.valueOf(p.getId()) + "] failed at conflict validation.");
                return new SimpleResponse(
                    messages, false);
            }
        } finally {
            lock.unlock();
        }

        /* If it makes it until here, conflict and context validation succeed. 
        Thus, we enforce the policy */
        enforcePolicy(p);
        messages.add("Policy [" + String.valueOf(p.getId()) + "] activated.");
        return new SimpleResponse(
            messages, true);
    }

    @Override
    public SimpleResponse deactivatePolicyById(int id) {

        PolicyRule pr;
        try {
            lock.lock();
            /* Looks for a policy with the given id in enforced state. 
            If it is not found, returns an error message */
            pr = getPolicyById(id, getActivePolicies());

            if (pr == null) {
                return new SimpleResponse(
                    "Policy [" + String.valueOf(id) + "] not in Enforced state", false);
            }

            // Move the policy to the pending state
            pr.setState(PolicyState.PENDING);
        } finally {
            lock.unlock();
        }
        // Tag the policy so it cannot be enforced until it is manually activated
        pr.setDeactivated(true);

        // Remove the policy from the network
        removePolicy(pr);

        CopyOnWriteArrayList<String> messages = new CopyOnWriteArrayList<>();
        messages.add("Policy [" + String.valueOf(id) + "] deactivated.");

        // Try to activate PENDING policies by priority order
        messages.add(activatePendingPolicies().getMessage());

        return new SimpleResponse(messages, true);
    }

    @Override
    public SimpleResponse deletePolicyById(int id) {

        // Looks for a policy with the given id. If it is not found, returns an error message
        PolicyRule pr;
        try {
            lock.lock();
            pr = getPolicyById(id);

            if (pr == null) {
                return new SimpleResponse(
                    "Policy [" + String.valueOf(id) + "] not found.", false);
            }
            // Remove the policy from the framework
            policies.getPolicyRules().remove(pr);
        } finally {
            lock.unlock();
        }

        // Remove the policy from the network
        removePolicy(pr);

        // If we have just deleted the last policy, reset the id
        if (policies.getPolicyRules().size() == 0) {
            resetUniqueId();
        }

        CopyOnWriteArrayList<String> messages = new CopyOnWriteArrayList<>();
        messages.add("Policy [" + String.valueOf(id) + "] deleted.");

        // Try to activate PENDING policies by priority order
        messages.add(activatePendingPolicies().getMessage());

        return new SimpleResponse(messages, true);
    }

    @Override
    public void deleteAllPolicyRules() {

        try {
            lock.lock();
            // Iterate over the ENFORCED policies
            for (PolicyRule pr : getActivePolicies().getPolicyRules()) {
                // Remove all the policies from the network
                removePolicy(pr);
            }
            // Remove all policy rules from the policy framework
            this.policies.setPolicyRules(new CopyOnWriteArrayList<>());
            resetUniqueId();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public SimpleResponse pushPolicies(PolicyRules policies) {
        // Get active policy rules (to check conflict with new policies)
        PolicyRules activePolicies = getActivePolicies();
        CopyOnWriteArrayList<PolicyRule> policyRules = policies.getPolicyRules();
        // restResponse initialization
        SimpleResponse sr, restResponse;

        List<Integer> ids = new CopyOnWriteArrayList<>();
        List<String> messages = new CopyOnWriteArrayList<>();

        int num_success = 0;
        int num_error = 0;

        int[] sortedIndices = IntStream.range(0, policies.getPolicyRules().size())
                                       .boxed().sorted(Comparator.comparing(policyRules::get))
                                       .mapToInt(ele -> ele).toArray();
        // Iterate over all the received policies
        for (int pos : sortedIndices) {
            PolicyRule pr = policyRules.get(pos);
            // Validate policy
            restResponse = validatePolicyRule(pr, activePolicies);
            if (isPendingPolicy(pr)) {
                restResponse.setCode(0);
                restResponse.setMessage("Duplicated policy.");
            }
            // If formal validation failed
            if (restResponse.getCode() == 0) {
                num_error += 1;

                // If conflict or context validation failed
            } else if (restResponse.getCode() == 1 || restResponse.getCode() == 2) {

                num_error += 1;

                // Give an id to this policy
                pr.setId(getUniqueId());

                // Add policy with PENDING state.
                addPolicy(pr);

                // All the validations succeed
            } else {

                num_success += 1;

                // Give an id to this policy
                pr.setId(getUniqueId());
                // Enforce policy
                enforcePolicy(pr);

                // Add policy with ENFORCED state
                addPolicy(pr);

                // Update active policies before the next iteration
                activePolicies = getActivePolicies();

            }
            ids.add(pr.getId());
            messages = restResponse.getMessages();
            for (String message : messages) {
                log.info("Debug: " + message);
            }
        }
        // If there is any error (create Status code 400 response)
        if (num_error > 0) {
            sr = new SimpleResponse(messages, false, ids);
            // If there is no error and at least one success (create Status code 200 response)
        } else if (num_success > 0) {
            sr = new SimpleResponse(messages, true, ids);
            // If there is no policy (create Status code 400 response)
        } else {
            sr = new SimpleResponse(400, "There is no new policy.", false);
        }
        return sr;
    }

    @Override
    public SimpleResponse changePolicyPriority(int id, int newPriority) {

        PolicyRule pr = getPolicyById(id);
        if (pr != null) {
            removePolicy(pr);
            pr.setPriority(newPriority);
            pr.setState(PolicyState.PENDING);

            SimpleResponse sr = activatePendingPolicies();

            List messages = new ArrayList();
            if (!sr.isSuccess()) {
                messages.add(sr.getMessage());
            }
            if (getPolicyById(id, getPoliciesByState(PolicyState.ENFORCED)) != null) {
                messages
                    .add("Priority successfully changed. Policy [" + String.valueOf(id) + "] enforced with priority " +
                         newPriority + ".");
                return new SimpleResponse(messages, true);
            } else {
                messages.add("Priority successfully changed. Policy [" +
                             String.valueOf(id) + "] moved to pending state with priority " + newPriority + ".");
                return new SimpleResponse(messages, true);
            }
        } else {
            return new SimpleResponse("Policy [" + String.valueOf(id) + "] not found.", false);
        }
    }

    @Override
    public void preprocess(PolicyRule pr) {
        pr.setType(pr.getType().toUpperCase());
        pr.setState(PolicyState.NEW);
        if (pr.getForm().equalsIgnoreCase("cnf")) {
            pr.setPolicyConditions(pr.cnf2dnf(pr.getPolicyConditions()));
            pr.setForm("DNF");
        }
        pr.sortConditions();
        Collections.sort(pr.getPolicyActions());
    }

    @Override
    public PolicyRules parsePolicyRules(String json) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        PolicyRules policyRules = null;
        try {
            policyRules = mapper.readValue(json, PolicyRules.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return policyRules;
    }

    @Override
    public SimpleResponse addPolicyType(String policyType) {
        if (!this.policyTypes.contains(policyType)) {
            this.policyTypes.add(policyType);
        }
        return new SimpleResponse("Policy type " + policyType +
                                  " successfully added", true);
    }

    @Override
    public SimpleResponse removePolicyType(String policyType) {
        if (this.policyTypes.contains(policyType)) {
            policyTypes.remove(policyType);
        }
        return new SimpleResponse("Policy type " + policyType +
                                  " successfully removed", true);
    }

    @Override
    public List<String> getPolicyTypes() {
        return this.policyTypes;
    }

    /**
     * Returns if a policy that we are trying to push is identical to any policy in pending state
     *
     * @param pr The policy rule to check its state
     */
    private boolean isPendingPolicy(PolicyRule pr) {
        for (PolicyRule pol : getPoliciesByState(PolicyState.PENDING).getPolicyRules()) {
            if (pol.equals(pr)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Validates a policy rule
     *
     * @param newPolicyRule  The policy to validate
     * @param activePolicies The list of active polices
     */
    private SimpleResponse validatePolicyRule(PolicyRule newPolicyRule,
                                              PolicyRules activePolicies) {

        SimpleResponse restResponse;
        List<String> messages = new CopyOnWriteArrayList<>();
        // Calls the formal validation
        restResponse = formalValidation(newPolicyRule);
        // If it fails it returns the error message with the code 0
        if (!restResponse.isSuccess()) {

            restResponse.setCode(0);

            return restResponse;
        }
        // If succeeds, changes the state to formally validated
        newPolicyRule.setState(PolicyState.FORMALLY_VALIDATED);

        // Then, calls the context validation
        restResponse = contextValidation(newPolicyRule);
        /* If it fails, it moves the policy to the Pending state and returns an
        error message with the code 2 */
        if (!restResponse.isSuccess()) {
            newPolicyRule.setState(PolicyState.PENDING);
            restResponse = new SimpleResponse(2, "Policy failed at context validation.", false);
            return restResponse;
        }
        // If succeeds, changes the state to context validated
        newPolicyRule.setState(PolicyState.CONTEXT_VALIDATED);


        // Finally, calls the conflict validator
        restResponse = conflictValidator(newPolicyRule, activePolicies);

        // If it fails
        if (!restResponse.isSuccess()) {
            // If has a code 2 it is a duplicated policy
            if (restResponse.getCode() == 2) {
                restResponse = new SimpleResponse(0, restResponse.getMessage(), false);
            }
            /* Otherwise, it is moved to the pending state and returns an error
            message with the code 1 */
            else {
                newPolicyRule.setState(PolicyState.PENDING);
                restResponse = new SimpleResponse(1, "Policy failed at conflict validation.", false);
            }
            return restResponse;
        }
        // If succeeds means that the policy has been enforced
        messages = restResponse.getMessages();
        messages.add(0, "Policy activated.");
        restResponse = new SimpleResponse(3, messages, true);
        return restResponse;
    }

    /**
     * Formally validates a policy.
     *
     * @param pr The policy rule to validate
     */
    private SimpleResponse formalValidation(PolicyRule pr) {
        // Checks that the policy type is registered
        if (!policyTypes.contains(pr.getType())) {
            return new SimpleResponse("Policy type " + pr.getType() +
                                      " not registered.", false);
        }

        // Connects with the formal validation endpoint of the policy type
        Response response =
            RESTtarget.path(pr.getType().toLowerCase() + "policy/formalvalidation")
                      .request()
                      .post(Entity.json(new ByteArrayInputStream(pr.toJSONString().getBytes())));

        // Returns the reply from the endpoint
        SimpleResponse restResponse;
        if (response.getStatus() == Status.OK.getStatusCode()) {
            restResponse = new SimpleResponse(response.readEntity(String.class), true);
        } else {
            restResponse = new SimpleResponse(response.readEntity(String.class), false);
        }
        response.close();
        if (restResponse.isSuccess()) {
            return selfConflictCheck(pr);
        }
        return restResponse;
    }

    /**
     * Check if a policy is conflicting with itself.
     *
     * @param pr The policy rule
     */
    private SimpleResponse selfConflictCheck(PolicyRule pr) {
        SimpleResponse restResponse = new SimpleResponse("Formally validated.", true);

        for (CopyOnWriteArrayList<PolicyCondition> clause : pr.getPolicyConditions()) {
            for (int j = 0; j < clause.size() - 1; j++) {
                for (int k = j + 1; k < clause.size(); k++) {
                    if (clause.get(j).getPolicyVariable().equalsIgnoreCase(clause.get(k).getPolicyVariable())) {
                        if (clause.get(j).getPolicyValue().equalsIgnoreCase(clause.get(k).getPolicyValue())) {
                            clause.remove(k);
                        } else {
                            return new SimpleResponse("Formal error: This policy has self-conflicting conditions.",
                                                      false);
                        }
                    }
                }
            }
        }
        CopyOnWriteArrayList<PolicyAction> pas = pr.getPolicyActions();
        for (int i = 0; i < pas.size() - 1; i++) {
            for (int j = i + 1; j < pas.size(); j++) {
                if (pas.get(i).getPolicyVariable().equalsIgnoreCase(pas.get(j).getPolicyVariable())) {
                    if (pas.get(i).getPolicyValue().equalsIgnoreCase(pas.get(j).getPolicyValue())) {
                        pas.remove(j);
                    } else {
                        return new SimpleResponse("Formal error: This policy has self-conflicting actions", false);
                    }
                }
            }

        }
        // Policy does not have conflicting conditions
        return restResponse;
    }

    /**
     * Context validates a policy.
     *
     * @param pr The policy rule to validate.
     */
    private SimpleResponse contextValidation(PolicyRule pr) {
        // Connects with the context validation enpoint of the policy type
        Response response = RESTtarget.path(pr.getType().toLowerCase() + "policy/contextvalidation")
                                      .request()
                                      .post(Entity.json(new ByteArrayInputStream(pr.toJSONString().getBytes())));

        // Returns the reply of the endpoint
        SimpleResponse restResponse;
        if (response.getStatus() == Status.OK.getStatusCode()) {
            restResponse = new SimpleResponse(response.getEntity().toString(), true);
        } else {
            restResponse = new SimpleResponse(response.getEntity().toString(), false);
        }
        response.close();
        return restResponse;
    }

    /**
     * Adds  the passed policy to the list of policies
     *
     * @param newPolicy PolicyRule to add
     */
    private void addPolicy(PolicyRule newPolicy) {
        this.policies.getPolicyRules().add(newPolicy);
    }

    /**
     * Returns a unique id
     */
    private int getUniqueId() {
        return uniqueId.incrementAndGet();
    }

    /**
     * Resets the id to 0
     */
    private void resetUniqueId() {
        this.uniqueId.set(0);
    }

    /**
     * Returns the policy with the given id.
     *
     * @param id       Policy identifier
     * @param policies PolicyRules object with the list of policy rules, where the
     *                 the PolicyRule with the given id should be found
     * @return PolicyRule with given id, or null.
     */
    private PolicyRule getPolicyById(int id, PolicyRules policies) {

        CopyOnWriteArrayList<PolicyRule> filteredPolicies = policies.getPolicyRules()
                                                                    .stream()
                                                                    .filter(policy -> policy.getId() == id)
                                                                    .collect(new PolicyCollector());
        if (filteredPolicies.isEmpty()) {
            return null;
        } else {
            return filteredPolicies.get(0);
        }
    }

    /**
     * Tries to activate the policies in Pending state.
     *
     * @return A SimpleResponse object with a success/failure message
     */
    private SimpleResponse activatePendingPolicies() {

        PolicyRules prs = getPoliciesByState(PolicyState.PENDING);
        Collections.sort(prs.getPolicyRules());

        if (prs.getPolicyRules().size() == 0) {
            return new SimpleResponse("No pending policies to activate", false);
        } else {
            ArrayList<Integer> enforced_ids = new ArrayList<>();
            for (PolicyRule pr : prs.getPolicyRules()) {
                // If the policy is tagged, it has to be kept as PENDING
                if (pr.isDeactivated()) {
                    continue;
                }
                if (contextValidation(pr).isSuccess()) {
                    try {
                        lock.lock();
                        if (conflictValidator(pr, getActivePolicies()).isSuccess()) {
                            // Enforce policy
                            enforcePolicy(pr);
                            // Update the active policies
                            enforced_ids.add(pr.getId());
                        }
                    } finally {
                        lock.unlock();
                    }
                }
            }
            if (enforced_ids.isEmpty()) {
                return new SimpleResponse("No pending policy could be activated.", false);
            } else {
                String idsString = enforced_ids.stream().map(Object::toString)
                                               .collect(Collectors.joining(", "));
                return new SimpleResponse("Policies [" + idsString + "] activated.", true);
            }
        }
    }

    /**
     * Checks if the given PolicyRule is in conflict with the policy rules
     * contained in the passed PolicyRules.
     *
     * @param npRule    the policy rule
     * @param activeprs the list of policy rules to check the conflict with.
     */
    private SimpleResponse conflictValidator(PolicyRule npRule, PolicyRules activeprs) {

        SimpleResponse sr = new SimpleResponse("Same-type conflict validated.", true);
        CopyOnWriteArrayList<String> messages = new CopyOnWriteArrayList<>();

        //if we have no rules then just return that conflict validation is OK
        if (activeprs.getPolicyRules().isEmpty()) {
            return sr;
        }
        /* Same policy type conflict validation
        apRule = active policy rule
        First step is conflict identification.
        Creates a list in which to host possible conflicting rules (crl).*/
        ArrayList<PolicyRule> crl = new ArrayList();
        for (PolicyRule apRule : activeprs.getPolicyRules()) { //only ACTIVATED policies
            // Add the rule to crl
            SimpleResponse sr_conflict = ConflictValidator.checkConflict(npRule, apRule);
            if (!sr_conflict.isSuccess()) {
                crl.add(apRule);
            }
        }
        /* Here crl should contain all conflicting rules. 
        Now we need to she which to keep, the new rule or the old rule set.*/
        SimpleResponse sr_resolution_result = ConflictValidator.conflictResolution(npRule, crl);
        if (sr_resolution_result.isSuccess()) {
            // Just return false and the policy will move to Pending state
            sr = new SimpleResponse("Policy failed at conflict validation", false);
        } else {
            /* New rule should be installed
            First deactivate old policies */
            for (PolicyRule ruleToDeactivate : crl) {
                deactivatePolicyById(ruleToDeactivate.getId());
                ruleToDeactivate.setDeactivated(false);
                messages.add("Policy [" + ruleToDeactivate.getId() + "] moved to pending state");
            }
            // Return true so that the policy will be activated
            messages.add("Policy passed conflict validation");
            sr = new SimpleResponse(messages, true);
        }
        return sr;
    }

    /**
     * Initial implementation of the conflict validation using the flow rules.
     */
    private SimpleResponse newConflictValidator(PolicyRule npRule) {
        SimpleResponse sr = new SimpleResponse("Conflict validated", true);
        ObjectMapper mapper = new ObjectMapper();
        Response response = RESTtarget.path(npRule.getType().toLowerCase() + "policy/rules")
                                      .request()
                                      .post(Entity.json(new ByteArrayInputStream(npRule.toJSONString().getBytes())));
        FlowRuleService flowRuleService = DefaultServiceDirectory.getService(FlowRuleService.class);
        DeviceService deviceService = DefaultServiceDirectory.getService(DeviceService.class);
        if (response.getStatus() != Status.OK.getStatusCode()) {
            sr = new SimpleResponse("Endpoint for conflict validation missing", false);
        } else {
            try {
                ForwardingObjectiveList forwardingObjectiveList =
                    mapper.readValue(response.getEntity().toString(), ForwardingObjectiveList.class);
                for (int i = 0; i < forwardingObjectiveList.getList().size(); i++) {
                    ForwardingObjective newEntry = forwardingObjectiveList.getList().get(i);
                    List<DeviceId> targetDevices = forwardingObjectiveList.getDevices().get(i);

                    for (Device d : deviceService.getDevices()) {
                        for (FlowEntry enforcedEntry : flowRuleService.getFlowEntries(d.id())) {
                            sr = ConflictValidator.newCheckConflict(enforcedEntry, newEntry, targetDevices);
                            if (!sr.isSuccess()) {
                                return sr;
                            }
                        }
                    }
                }
                forwardingObjectiveList.getDevices();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return sr;
    }

    /**
     * Enforces a policy rule in the underlying network by calling the
     * corresponding endpoint of the policy type app.
     *
     * @param pr The policy rule to enforce
     */
    private void enforcePolicy(PolicyRule pr) {

        Response response = RESTtarget.path(pr.getType().toLowerCase() + "policy/enforce").request()
                                      .post(Entity.json(new ByteArrayInputStream(pr.toJSONString().getBytes())));
        pr.setState(PolicyState.ENFORCED);
        if (response.getStatus() == Status.OK.getStatusCode()) {
            log.info("Policy successfuly enforced");
        }
        response.close();
    }

    /**
     * Removes a policy rule from the underlying network by calling the
     * corresponding endpoint of the policy type app.
     *
     * @param pr The policy rule to remove
     */
    private void removePolicy(PolicyRule pr) {
        Response response = RESTtarget.path(pr.getType().toLowerCase() + "policy/remove").request()
                                      .post(Entity.json(new ByteArrayInputStream(pr.toJSONString().getBytes())));

        if (response.getStatus() == Status.OK.getStatusCode()) {
            log.info("Policy successfuly removed");
        }
        response.close();
    }
}
