package eu.ngpaas.pmlib;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.google.common.primitives.Ints;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a response message to a REST request
 */
@JsonSerialize(using = SimpleResponseSerializer.class)
public class SimpleResponse {
    private final Logger log = LoggerFactory.getLogger(getClass());

    /**
     * Represents a code to the response. If not specified in the constructor,
     * is assigned based on the "success" attribute
     */
    private int code;

    /**
     * True for successful actions, false otherwise
     */
    private boolean success;

    /**
     * List of ids assigned to the new policies (formally validated). If not
     * specified in the constructor it is null.
     */
    private List<Integer> policy_ids;

    /**
     * List of messages to reply
     */
    private List<String> messages = new ArrayList<>();

    @JsonIgnore
    private Boolean operation;

    public SimpleResponse() {
    }

    /**
     * Constructs a SimpleResponse based on a single message and a success boolean
     *
     * @param message the message
     * @param success true or false
     * @return a SimpleResponse object
     */
    public SimpleResponse(String message, boolean success) {
        if (success) {
            this.code = 200;
        } else {
            this.code = 400;
        }
        this.messages.add(message);
        this.success = success;
        this.policy_ids = null;
    }

    /**
     * Constructs a SimpleResponse based on a list of messages, a success boolean, and
     * a list of ids.
     *
     * @param messages   the message
     * @param success    true or false
     * @param policy_ids list of ids
     * @return a SimpleResponse object
     */
    public SimpleResponse(List<String> messages, boolean success, List<Integer> policy_ids) {
        if (success) {
            this.code = 200;
        } else {
            this.code = 400;
        }
        this.messages = messages;
        this.success = success;
        this.policy_ids = policy_ids;
    }

    /**
     * Constructs a SimpleResponse based on a list of messages and a success boolean
     *
     * @param messages list of messages
     * @param success  true or false
     * @return a SimpleResponse object
     */
    public SimpleResponse(List<String> messages, boolean success) {
        if (success) {
            this.code = 200;
        } else {
            this.code = 400;
        }
        this.messages = messages;
        this.success = success;
    }

    /**
     * Constructs a SimpleResponse based on a message and a code
     *
     * @param message a message
     * @param code    an integer
     * @return a SimpleResponse object
     */
    public SimpleResponse(String message, int code) {
        this.code = code;
        this.success = code == 200;
        this.messages.add(message);
        this.policy_ids = null;
    }

    /**
     * Constructs a SimpleResponse based on a code, a message, and a success boolean
     *
     * @param code    an integer
     * @param message a message
     * @param success true or false
     * @return a SimpleResponse object
     */
    public SimpleResponse(int code, String message, boolean success) {
        this.code = code;
        this.messages.add(message);
        this.success = success;
        this.policy_ids = null;
    }

    /**
     * Constructs a SimpleResponse based on a code, a message, and a success boolean
     *
     * @param code     an integer
     * @param messages a list of message
     * @param success  true or false
     * @return a SimpleResponse object
     */
    public SimpleResponse(int code, List<String> messages, boolean success) {
        this.code = code;
        this.messages = messages;
        this.success = success;
        this.policy_ids = null;
    }

    /**
     * Returns the success attribute
     *
     * @return true or false
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * Returns the code attribute
     *
     * @return the code
     */
    public int getCode() {
        return code;
    }

    /**
     * Sets the code attribute
     *
     * @param code the code
     */
    public void setCode(int code) {
        this.code = code;
    }

    /**
     * Returns the list of messages
     *
     * @return the list of messages
     */
    public List<String> getMessages() {
        return messages;
    }

    /**
     * Returns the first message of the list
     *
     * @return the code
     */
    public String getMessage() {
        return messages.get(0);
    }

    /**
     * Sets the message
     *
     * @param message the message
     */
    public void setMessage(String message) {
        this.messages.set(0, message);
    }

    /**
     * Returns the list of ids
     *
     * @return the list of ids
     */
    public List<Integer> getPolicy_ids() {
        return policy_ids;
    }

    /**
     * Parses a Simple Response object to JSON
     *
     * @return a JSON string
     */
    public String toJSON() {

        ObjectMapper mapper = new ObjectMapper();

        String json = null;

        try {
            json = mapper.writeValueAsString(this);

        } catch (JsonProcessingException e) {

            e.printStackTrace();
        }
        log.info(json);
        return json;

    }

}

/**
 * Represents a serializer class of the SimpleResponse class
 */
class SimpleResponseSerializer extends StdSerializer<SimpleResponse> {
    private SimpleResponseSerializer() {
        this(null);
    }

    private SimpleResponseSerializer(Class<SimpleResponse> t) {
        super(t);
    }

    @Override
    public void serialize(SimpleResponse sr, JsonGenerator jgen, SerializerProvider serializerProvider)
        throws IOException {
        jgen.writeStartObject();
        jgen.writeNumberField("code", sr.getCode());
        if (sr.getPolicy_ids() != null) {
            int[] ids = Ints.toArray(sr.getPolicy_ids());
            jgen.writeFieldName("ids");
            jgen.writeArray(ids, 0, ids.length);

        }
        jgen.writeArrayFieldStart("messages");
        for (String msg : sr.getMessages()) {
            jgen.writeString(msg);
        }
        jgen.writeEndArray();
        jgen.writeBooleanField("success", sr.isSuccess());
        jgen.writeEndObject();
    }
}
