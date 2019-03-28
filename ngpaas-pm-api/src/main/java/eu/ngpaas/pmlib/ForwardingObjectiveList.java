package eu.ngpaas.pmlib;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.onosproject.codec.impl.ForwardingObjectiveCodec;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.rest.AbstractWebResource;

/**
 * Represents a list of ForwardingObjectives, each of them to be enforced in a list of
 * devices.
 */
@JsonSerialize(using = ForwardingObjectiveListSerializer.class)
@JsonDeserialize(using = ForwardingObjectiveListDeserializer.class)
public class ForwardingObjectiveList {
    private List<ForwardingObjective> list;
    private List<List<DeviceId>> devices;

    public ForwardingObjectiveList() {
        this.list = new ArrayList<>();
        this.devices = new ArrayList<>();
    }

    public List<ForwardingObjective> getList() {
        return list;
    }

    public List<List<DeviceId>> getDevices() {
        return devices;
    }

}

/**
 * Serializes a ForwardingObjectiveList into JSON
 */
class ForwardingObjectiveListSerializer extends StdSerializer<ForwardingObjectiveList> {


    public ForwardingObjectiveListSerializer() {
        this(null);
    }

    public ForwardingObjectiveListSerializer(Class<ForwardingObjectiveList> t) {
        super(t);
    }

    @Override
    public void serialize(ForwardingObjectiveList forwardingObjectiveList,
                          JsonGenerator jgen, SerializerProvider serializerProvider) throws IOException {
        ForwardingObjectiveCodec fwdObjCodec = new ForwardingObjectiveCodec();
        AbstractWebResource awr = new AbstractWebResource();
        jgen.writeStartObject();
        jgen.writeArrayFieldStart("objectives");
        for (ForwardingObjective fwdObj : forwardingObjectiveList.getList()) {
            jgen.writeString(fwdObjCodec.encode(fwdObj, awr).toString());
        }
        jgen.writeEndArray();
        jgen.writeArrayFieldStart("devices");
        for (List<DeviceId> deviceIdList : forwardingObjectiveList.getDevices()) {
            jgen.writeStartArray();
            for (DeviceId deviceId : deviceIdList) {
                jgen.writeString(deviceId.toString());
            }
            jgen.writeEndArray();
        }
        jgen.writeEndArray();
        jgen.writeEndObject();
    }


}

/**
 * Deserializes a JSON string into a ForwardingObjectiveList
 */
class ForwardingObjectiveListDeserializer extends StdDeserializer<ForwardingObjectiveList> {

    public ForwardingObjectiveListDeserializer() {
        this(null);
    }

    public ForwardingObjectiveListDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public ForwardingObjectiveList deserialize(JsonParser jp, DeserializationContext ctxt)
        throws IOException, JsonProcessingException {
        JsonNode node = jp.getCodec().readTree(jp);
        ForwardingObjectiveList fwdObjList = new ForwardingObjectiveList();
        ForwardingObjectiveCodec fwdObjCodec = new ForwardingObjectiveCodec();
        AbstractWebResource awr = new AbstractWebResource();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = node.get("objectives");
        for (int i = 0; i < jsonNode.size(); i++) {
            fwdObjList.getList().add(fwdObjCodec.decode(
                (ObjectNode) mapper.readTree(jsonNode.get(i).asText()), awr));
        }
        jsonNode = node.get("devices");
        for (int i = 0; i < jsonNode.size(); i++) {
            fwdObjList.getDevices().add(new ArrayList<>());
            for (int j = 0; j < jsonNode.get(i).size(); j++) {
                fwdObjList.getDevices().get(i).add(DeviceId.deviceId(
                    jsonNode.get(i).get(j).toString()));
            }
        }
        return fwdObjList;
    }
}