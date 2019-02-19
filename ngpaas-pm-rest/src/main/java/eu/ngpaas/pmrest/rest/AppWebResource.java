/*
 * Copyright 2018-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.ngpaas.pmrest.rest;

import eu.ngpaas.pmLib.PolicyRule;
import eu.ngpaas.pmLib.PolicyRules;
import eu.ngpaas.pmLib.PolicyState;
import eu.ngpaas.pmLib.SimpleResponse;
import eu.ngpaas.pmrest.core.PolicyFrameworkService;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.onosproject.rest.AbstractWebResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@Path("")
public class AppWebResource extends AbstractWebResource {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private PolicyFrameworkService policyFrameworkService = get(PolicyFrameworkService.class);

    @GET
    @Path("policies")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPolicies() {
        return ok(policyFrameworkService.getAllPolicies().toJSONString()).
                status(200).
                build();
    }

    @GET
    @Path("policies/active")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getActivePolicies() {
        return ok(policyFrameworkService.getActivePolicies().toJSONString()).
                status(200).
                build();
    }

    @GET
    @Path("policies/id/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPolicy(@PathParam("id")int id) {

        PolicyRule pr = policyFrameworkService.getPolicyById(id);

        if (pr == null) {

            SimpleResponse sr = new SimpleResponse("No Policy with ID " + 
                String.valueOf(id), false);

            log.info("No Policy with ID " + String.valueOf(id));

            return ok(sr.toJSON())
                    .status(sr.getCode())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } else {
            PolicyRules prs = new PolicyRules();
            prs.addRule(pr);
            return ok(prs.toJSONString()).
                    status(200).
                    build();
        }
    }

    @GET
    @Path("policies/state/{state}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPoliciesByState(@PathParam("state")String state) {
        return ok(policyFrameworkService.getPoliciesByState(PolicyState.fromString(state)).toJSONString())
            .status(200)
            .build();
    }

    @GET
    @Path("policies/type/{type}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPolicyByType(@PathParam("type")String type) {
        return ok(policyFrameworkService.getPoliciesByType(type).toJSONString())
            .status(200)
            .build();
    }

    @GET
    @Path("policies/num/")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getNumberOfPolicies(){

        int num_of_policies = policyFrameworkService.getNumberOfPolicies();
        SimpleResponse sr = new SimpleResponse(
                "The number of policies is "+String.valueOf(num_of_policies),
                true
        );

        return ok(sr.toJSON()).
                status(sr.getCode()).
                build();
    }

    @GET
    @Path("policies/types/")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPolicyTypes(){

        List<String> policyTypes = policyFrameworkService.getPolicyTypes();
        SimpleResponse sr;
        if (!policyTypes.isEmpty()){
             sr = new SimpleResponse(policyTypes, true);
        } else{
            sr = new SimpleResponse("No policy types available", true);
        }
        return ok(sr.toJSON()).
                status(sr.getCode()).
                build();
    }

    @POST
    @Path("policies")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response setNewPolicy(String body) {

        log.info("Request received");

        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

        SimpleResponse sr;

        PolicyRules policyRules = policyFrameworkService.parsePolicyRules(body);
        if (policyRules == null){
            sr = new SimpleResponse("Error when parsing the JSON structure", false);
            return ok(sr.toJSON())
                    .status(400)
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } else if (policyRules.getPolicyRules().isEmpty()){
            sr = new SimpleResponse("Empty policy provided", false);
            return ok(sr.toJSON())
                    .status(400)
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } else {
            for (PolicyRule pr : policyRules.getPolicyRules()){
                if (pr.getPriority() < 1 || pr.getPolicyConditions().isEmpty() 
                    || pr.getPolicyActions().isEmpty() || pr.getType()==null 
                    || pr.getForm() == null){
                    sr = new SimpleResponse("Invalid policy provided. You MUST" +
                     " provide a policy with a priority higher than 0, of a valid" +
                     " type and form, with non-empty conditions and actions", false);
                    return ok(sr.toJSON())
                            .status(400)
                            .type(MediaType.APPLICATION_JSON)
                            .build();
                }
            }
        }
        PolicyRules processed_prs = new PolicyRules();

        for (PolicyRule pr: policyRules.getPolicyRules()){
                policyFrameworkService.preprocess(pr);
            processed_prs.getPolicyRules().add(pr);
        }
        sr = policyFrameworkService.pushPolicies(processed_prs);

        return ok(sr.toJSON())
                .status(sr.getCode())
                .build();
    }

    @GET
    @Path("policies/activate/{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response activatePolicyById(@PathParam("id")int id){

        SimpleResponse sr = policyFrameworkService.activatePolicyById(id);

        return ok(sr.toJSON()).
                status(sr.getCode()).
                build();
    }

    @DELETE
    @Path("policies/deactivate/{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response deactivatePolicyById(@PathParam("id")int id){

        SimpleResponse sr = policyFrameworkService.deactivatePolicyById(id);

        return ok(sr.toJSON()).
                status(sr.getCode()).
                build();
    }

    @DELETE
    @Path("policies/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteById(@PathParam("id")int id){

        SimpleResponse sr = policyFrameworkService.deletePolicyById(id);

        return ok(sr.toJSON()).
                status(sr.getCode()).
                build();
    }

    @DELETE
    @Path("policies")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteAll(){

        policyFrameworkService.deleteAllPolicyRules();

        SimpleResponse sr = new SimpleResponse("All policies deleted", true);

        return ok(sr.toJSON()).
                status(sr.getCode()).
                build();
    }

    @PUT
    @Path("policies/{id}/priority/{newPriority}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response changePriority(@PathParam("id")int id, 
        @PathParam("newPriority")int newPriority){

        SimpleResponse sr = policyFrameworkService.changePolicyPriority(id, newPriority);

        return ok(sr.toJSON()).
                status(sr.getCode()).
                build();
    }

    @PUT
    @Path("policytype/register/{policyType}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerPolicyType(@PathParam("policyType")String policyType){

        SimpleResponse sr = policyFrameworkService.addPolicyType(policyType.toUpperCase());

        return ok(sr.getMessage()).
                status(sr.getCode()).
                build();
    }
    @DELETE
    @Path("policytype/deregister/{policyType}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deregisterPolicyType(@PathParam("policyType")String policyType){
        log.info("Received request to de-register "+policyType);
        log.info("Collecting soon to be orphan policy instances");
        PolicyRules policyRules = policyFrameworkService.getPoliciesByType(policyType.toUpperCase());
        SimpleResponse sr = policyFrameworkService.removePolicyType(policyType.toUpperCase());
        for(PolicyRule pr : policyFrameworkService.getPoliciesByType(policyType.toUpperCase()).getPolicyRules()){
            policyFrameworkService.deletePolicyById(pr.getId());
        }
        log.info("Policy type de-registered");
        log.info("Sending orphan policy rules to Policy Manager");
        return ok(sr.getMessage()).
                entity(policyRules.toJSONString()).
                status(sr.getCode()).
                build();
    }
}
