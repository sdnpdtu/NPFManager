package eu.ngpaas.pmlib;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.commons.collections.CollectionUtils;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TpPort;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.EthTypeCriterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.IPProtocolCriterion;
import org.onosproject.net.flow.criteria.TcpPortCriterion;
import org.onosproject.net.flow.criteria.UdpPortCriterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flow.instructions.L2ModificationInstruction;
import org.onosproject.net.flow.instructions.L3ModificationInstruction;
import org.onosproject.net.flow.instructions.L4ModificationInstruction;
import org.onosproject.net.flowobjective.ForwardingObjective;

/**
 * Analyzes the conflict between policies
 */
public final class ConflictValidator {

    /**
     * Identifies if there is a conflict between a pair of policy rules
     *
     * @param npRule a new policy rule
     * @param apRule an active policy rule
     * @return a SimpleResponse object with the success/fail message
     */
    public static SimpleResponse checkConflict(PolicyRule npRule, PolicyRule apRule) {

        SimpleResponse sr = new SimpleResponse(0, "No conflict", true);
        // If the policies are of different types there is no conflict.
        if (!npRule.getType().equals(apRule.getType())) {
            return sr;
        }

        // Otherwise, if all conditions are independent, there is no conflict.
        if (allConditionsIndependent(apRule.getPolicyConditions(), npRule.getPolicyConditions())) {
            return sr;
        }

        // Otherwise, if the actions are equal, there is no conflict.
        if (npRule.equalPolicyActions(apRule)) {
            if (npRule.equalPolicyConditions(apRule)) {
                npRule.setId(apRule.getId());
                return new SimpleResponse(2, "Duplicated policy.", false);
            } else {
                return sr;
            }
        }

        // Otherwise, there is a conflict
        if (npRule.getPriority() != apRule.getPriority()) {
            return new SimpleResponse(1, "There is conflict.", false);
        }

        // Otherwise (i.e., same type, dependent, different actions and same priority), there is conflict.
        return new SimpleResponse(1, "There is conflict.", false);
    }

    /**
     * Implements the conflict resolution logic between a pair of policy rules
     *
     * @param npRule a new policy rule
     * @param crl    a list of active policy rules
     * @return a SimpleResponse object with the success/fail message
     */
    public static SimpleResponse conflictResolution(PolicyRule npRule, ArrayList<PolicyRule> crl) {
        /* There are two cases that should be taken into account.
            1. npRule has a higher priority compared with all rules in crl --> Put all rules in crl in Pending state
            and clean flow tables
            2. At least one rule from crl has a higher or equal priority to npRule --> Keep the rules in crl as
            active and move npRule to Pending
           use a boolean flag to identify the two cases */
        boolean keepOldRules = false;
        for (PolicyRule apRule : crl) {
            if (apRule.getPriority() >= npRule.getPriority()) {
                keepOldRules = true;
            }
        }
        if (keepOldRules) {
            return new SimpleResponse(0, "Keep old policies", true);
        } else {
            return new SimpleResponse(1, "Add new policy", false);

        }
    }

    /**
     * Identifies if there is conflict based on the flow entries of the switches
     *
     * @param enforcedEntry an enforced entry
     * @param newEntry      a new entry
     * @param targetDevices a list of devices where to analyze the conflict
     * @return a SimpleResponse object with the success/fail message
     */
    public static SimpleResponse newCheckConflict(FlowEntry enforcedEntry, ForwardingObjective newEntry,
                                                  List<DeviceId> targetDevices) {
        SimpleResponse sr = new SimpleResponse("No conflict", true);
        if ((enforcedEntry.priority() != newEntry.priority()) || !targetDevices.contains(enforcedEntry.deviceId())) {
            return sr;
        }

        EthCriterion enforced_ethc, new_ethc;
        TcpPortCriterion enforced_tcppc, new_tcppc;
        UdpPortCriterion enforced_udppc, new_udppc;

        for (Criterion enforcedCriteria : enforcedEntry.selector().criteria()) {
            for (Criterion newCriteria : newEntry.selector().criteria()) {
                if (enforcedCriteria.type() != newCriteria.type()) {
                    continue;
                }

                switch (enforcedCriteria.type()) {
                    case ETH_TYPE:
                        EthTypeCriterion enforced_etc = (EthTypeCriterion) enforcedCriteria;
                        EthTypeCriterion new_etc = (EthTypeCriterion) newCriteria;
                        if (enforced_etc.ethType() != new_etc.ethType()) {
                            return sr;
                        }
                        break;
                    case IP_PROTO:
                        IPProtocolCriterion enforced_ippc = (IPProtocolCriterion) enforcedCriteria;
                        IPProtocolCriterion new_ippc = (IPProtocolCriterion) newCriteria;
                        if (enforced_ippc.protocol() != new_ippc.protocol()) {
                            return sr;
                        }
                        break;
                    case IPV4_SRC:
                    case IPV4_DST:
                        IPCriterion enforced_ipc = (IPCriterion) enforcedCriteria;
                        IPCriterion new_ipc = (IPCriterion) newCriteria;
                        if (!checkCidrInCidr(new_ipc.ip().getIp4Prefix(), enforced_ipc.ip().getIp4Prefix())) {
                            return sr;
                        }
                        break;
                    case ETH_SRC:
                    case ETH_DST:
                        enforced_ethc = (EthCriterion) enforcedCriteria;
                        new_ethc = (EthCriterion) newCriteria;
                        if (!Long.valueOf(enforced_ethc.mac().toLong()).equals(new_ethc.mac().toLong())) {
                            return sr;
                        }
                        break;
                    case ETH_SRC_MASKED:
                    case ETH_DST_MASKED:
                        enforced_ethc = (EthCriterion) enforcedCriteria;
                        new_ethc = (EthCriterion) newCriteria;
                        if (!checkMacInMac(new_ethc.mac(), new_ethc.mask(), enforced_ethc.mac(),
                                           enforced_ethc.mask())) {
                            return sr;
                        }
                        break;
                    case TCP_SRC:
                    case TCP_DST:
                        enforced_tcppc = (TcpPortCriterion) enforcedCriteria;
                        new_tcppc = (TcpPortCriterion) newCriteria;
                        if (enforced_tcppc.tcpPort() != new_tcppc.tcpPort()) {
                            return sr;
                        }
                        break;
                    case TCP_SRC_MASKED:
                    case TCP_DST_MASKED:
                        enforced_tcppc = (TcpPortCriterion) enforcedCriteria;
                        new_tcppc = (TcpPortCriterion) newCriteria;
                        if (!checkPortInPort(new_tcppc.tcpPort(), new_tcppc.mask(), enforced_tcppc.tcpPort(),
                                             enforced_tcppc.mask())) {
                            return sr;
                        }
                        break;
                    case UDP_SRC:
                    case UDP_DST:
                        enforced_udppc = (UdpPortCriterion) enforcedCriteria;
                        new_udppc = (UdpPortCriterion) newCriteria;
                        if (enforced_udppc.udpPort() != new_udppc.udpPort()) {
                            return sr;
                        }
                        break;
                    case UDP_SRC_MASKED:
                    case UDP_DST_MASKED:
                        enforced_udppc = (UdpPortCriterion) enforcedCriteria;
                        new_udppc = (UdpPortCriterion) newCriteria;
                        if (!checkPortInPort(new_udppc.udpPort(), new_udppc.mask(), enforced_udppc.udpPort(),
                                             enforced_udppc.mask())) {
                            return sr;
                        }
                        break;
                }


            }
        }
        SimpleResponse sr2 = new SimpleResponse("Policy failed in conflict validation", false);
        //If we arrive here we know for sure that the flow entries are not independent. If they perform different
        // actions, that will be a conflict.
        for (Instruction newInstruction : newEntry.treatment().allInstructions()) {
            boolean matched = false;
            for (Instruction enforcedInstruction : enforcedEntry.treatment().allInstructions()) {
                if (enforcedInstruction.type() != newInstruction.type()) {
                    continue;
                }
                switch (enforcedInstruction.type()) {
                    case NOACTION: //DROP
                        matched = true;
                        break;
                    case OUTPUT:
                        Instructions.OutputInstruction enforced_output = (Instructions.OutputInstruction)
                            enforcedInstruction;
                        Instructions.OutputInstruction new_output = (Instructions.OutputInstruction) newInstruction;
                        if (!enforced_output.port().equals(new_output.port())) {
                            return sr2;
                        }
                        matched = true;
                        break;
                    case L2MODIFICATION:
                        L2ModificationInstruction enforced_l2mod = (L2ModificationInstruction) enforcedInstruction;
                        L2ModificationInstruction new_l2mod = (L2ModificationInstruction) newInstruction;
                        if (enforced_l2mod.subtype() != new_l2mod.subtype()) {
                            continue;
                        }
                        switch (enforced_l2mod.subtype()) {
                            case ETH_SRC:
                            case ETH_DST:
                                L2ModificationInstruction.ModEtherInstruction enforced_l2modethi =
                                    (L2ModificationInstruction.ModEtherInstruction) enforced_l2mod;
                                L2ModificationInstruction.ModEtherInstruction new_l2modethi =
                                    (L2ModificationInstruction.ModEtherInstruction) new_l2mod;
                                if (!Long.valueOf(enforced_l2modethi.mac().toLong())
                                         .equals(new_l2modethi.mac().toLong())) {
                                    return sr2;
                                }
                                matched = true;
                                break;
                        }
                        break;
                    case L3MODIFICATION:
                        L3ModificationInstruction enforced_l3mod = (L3ModificationInstruction) enforcedInstruction;
                        L3ModificationInstruction new_l3mod = (L3ModificationInstruction) newInstruction;
                        if (enforced_l3mod.subtype() != new_l3mod.subtype()) {
                            continue;
                        }
                        switch (enforced_l3mod.subtype()) {
                            case IPV4_SRC:
                            case IPV4_DST:
                                L3ModificationInstruction.ModIPInstruction enforced_l3modethi =
                                    (L3ModificationInstruction.ModIPInstruction) enforced_l3mod;
                                L3ModificationInstruction.ModIPInstruction new_l3modethi = (L3ModificationInstruction
                                    .ModIPInstruction) new_l3mod;
                                if (!new_l3modethi.ip().equals(enforced_l3modethi.ip())) {
                                    return sr2;
                                }
                                matched = true;
                                break;
                        }
                        break;
                    case L4MODIFICATION:
                        L4ModificationInstruction enforced_l4mod = (L4ModificationInstruction) enforcedInstruction;
                        L4ModificationInstruction new_l4mod = (L4ModificationInstruction) newInstruction;
                        if (enforced_l4mod.subtype() != new_l4mod.subtype()) {
                            continue;
                        }
                        switch (enforced_l4mod.subtype()) {
                            case TCP_SRC:
                            case TCP_DST:
                            case UDP_SRC:
                            case UDP_DST:
                                L4ModificationInstruction.ModTransportPortInstruction enforced_l4modtpi =
                                    (L4ModificationInstruction.ModTransportPortInstruction) enforced_l4mod;
                                L4ModificationInstruction.ModTransportPortInstruction new_l4modtpi =
                                    (L4ModificationInstruction.ModTransportPortInstruction) new_l4mod;
                                if (enforced_l4modtpi.port().toInt() != new_l4modtpi.port().toInt()) {
                                    return sr2;
                                }
                                matched = true;
                                break;
                        }
                        break;
                }
            }
            if (!matched) {
                return sr2;
            }
        }
        return sr;
    }

    /**
     * Checks if a CIDR is contained in another CIDR
     *
     * @param cidrAddr1 address 1
     * @param cidrAddr2 address 2
     * @return true or false
     */
    private static boolean checkCidrInCidr(Ip4Prefix cidrAddr1, Ip4Prefix cidrAddr2) {
        if (cidrAddr2 == null) {
            return true;
        } else if (cidrAddr1 == null) {
            return false;
        }
        if (cidrAddr1.prefixLength() < cidrAddr2.prefixLength()) {
            return false;
        }
        int offset = 32 - cidrAddr2.prefixLength();

        int cidr1Prefix = cidrAddr1.address().toInt();
        int cidr2Prefix = cidrAddr2.address().toInt();
        cidr1Prefix = cidr1Prefix >> offset;
        cidr2Prefix = cidr2Prefix >> offset;
        cidr1Prefix = cidr1Prefix << offset;
        cidr2Prefix = cidr2Prefix << offset;

        return (cidr1Prefix == cidr2Prefix);
    }

    /**
     * Checks if a MAC address is contained in another MAC address
     *
     * @param mac1  mac address 1
     * @param mask1 mask of mac1
     * @param mac2  mac address 2
     * @param mask2 mask of mac2
     * @return true or false
     */
    private static boolean checkMacInMac(MacAddress mac1, MacAddress mask1, MacAddress mac2, MacAddress mask2) {
        return ((mac1.toLong() & mask1.toLong()) == (mac2.toLong() & mask2.toLong()));
    }

    /**
     * Checks if a Port is contained in another Port
     *
     * @param port1 port 1
     * @param mask1 mask of port1
     * @param port2 port 2
     * @param mask2 mask of port2
     * @return true or false
     */
    private static boolean checkPortInPort(TpPort port1, TpPort mask1, TpPort port2, TpPort mask2) {
        return ((port1.toInt() & mask1.toInt()) == (port2.toInt() & mask2.toInt()));
    }

    /**
     * Checks if the conditions of a pair policies are independent
     *
     * @param apcs conditions of an active policy rule
     * @param npcs conditions of a new policy rule
     * @return true or false
     */
    private static Boolean allConditionsIndependent(CopyOnWriteArrayList<CopyOnWriteArrayList<PolicyCondition>> apcs,
                                                    CopyOnWriteArrayList<CopyOnWriteArrayList<PolicyCondition>> npcs) {
        ArrayList<String> intersection;
        Map<String, String> activeClauseDict;
        Map<String, String> newClauseDict;

        int nindep = 0;

        for (CopyOnWriteArrayList<PolicyCondition> activeClause : apcs) {
            for (CopyOnWriteArrayList<PolicyCondition> newClause : npcs) {
                activeClauseDict = getPolicyVariablesDict(activeClause);
                newClauseDict = getPolicyVariablesDict(newClause);
                intersection = (ArrayList<String>) CollectionUtils
                    .intersection(activeClauseDict.keySet(), newClauseDict.keySet());
                if (intersection.isEmpty()) {
                    return false;
                } else {
                    for (String pv : intersection) {
                        if (!activeClauseDict.get(pv).equalsIgnoreCase(newClauseDict.get(pv))) {
                            nindep++;
                            break;
                        }
                    }
                }
            }
        }
        return nindep == apcs.size() * npcs.size();
    }

    /**
     * Creates a dictionary based on the PolicyVariable and PolicyValue of a PolicyCondition
     *
     * @param clause list of policy conditions
     */
    private static Map<String, String> getPolicyVariablesDict(CopyOnWriteArrayList<PolicyCondition> clause) {
        Map<String, String> policyVariablesDict = new HashMap<>();
        for (PolicyCondition pc : clause) {
            policyVariablesDict.put(pc.getPolicyVariable(), pc.getPolicyValue());
        }
        return policyVariablesDict;
    }
}
