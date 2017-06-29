package org.springframework.security.oauth2.provider.token.store.jwk;

import java.util.List;

/**
 * Created by jihunlee on 2017. 6. 29..
 */
class JwkMemberValue {
    private final ValueType valueType;
    private final String stringValue;
    private final List<String> arrayValue;

    JwkMemberValue(String stringValue) {
        this.valueType = ValueType.STRING;
        this.stringValue = stringValue;
        this.arrayValue = null;
    }

    JwkMemberValue(List<String> arrayValue) {
        this.valueType = ValueType.ARRAY;
        this.arrayValue = arrayValue;
        this.stringValue = null;
    }

    public ValueType getValueType() {
        return valueType;
    }

    public String getStringValue() {
        return stringValue;
    }

    public List<String> getArrayValue() {
        return arrayValue;
    }

    enum ValueType {
        STRING,
        ARRAY
    }
}
