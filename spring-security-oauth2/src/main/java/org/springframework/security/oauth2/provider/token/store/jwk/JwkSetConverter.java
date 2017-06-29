/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.token.store.jwk;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import org.apache.commons.codec.binary.Base64;
import org.springframework.core.convert.converter.Converter;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.springframework.security.oauth2.provider.token.store.jwk.JwkAttributes.*;

/**
 * A {@link Converter} that converts the supplied <code>InputStream</code> to a <code>Set</code> of {@link JwkDefinition}(s).
 * The source of the <code>InputStream</code> <b>must be</b> a JWK Set representation which is a JSON object
 * that has a &quot;keys&quot; member and its value is an array of JWKs.
 * <br>
 * <br>
 *
 * <b>NOTE:</b> The Key Type (&quot;kty&quot;) currently supported by this {@link Converter} is {@link JwkDefinition.KeyType#RSA}.
 * <br>
 * <br>
 *
 * @see JwkDefinition
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517#page-10">JWK Set Format</a>
 *
 * @author Joe Grandja
 */
class JwkSetConverter implements Converter<InputStream, Set<JwkDefinition>> {
	private final JsonFactory factory = new JsonFactory();

	/**
	 * Converts the supplied <code>InputStream</code> to a <code>Set</code> of {@link JwkDefinition}(s).
	 *
	 * @param jwkSetSource the source for the JWK Set
	 * @return a <code>Set</code> of {@link JwkDefinition}(s)
	 * @throws JwkException if the JWK Set JSON object is invalid
	 */
	@Override
	public Set<JwkDefinition> convert(InputStream jwkSetSource) {
		Set<JwkDefinition> jwkDefinitions;
		JsonParser parser = null;

		try {
			parser = this.factory.createParser(jwkSetSource);

			if (parser.nextToken() != JsonToken.START_OBJECT) {
				throw new JwkException("Invalid JWK Set Object.");
			}
			if (parser.nextToken() != JsonToken.FIELD_NAME) {
				throw new JwkException("Invalid JWK Set Object.");
			}
			if (!parser.getCurrentName().equals(KEYS)) {
				throw new JwkException("Invalid JWK Set Object. The JWK Set MUST have a " + KEYS + " attribute.");
			}
			if (parser.nextToken() != JsonToken.START_ARRAY) {
				throw new JwkException("Invalid JWK Set Object. The JWK Set MUST have an array of JWK(s).");
			}

			jwkDefinitions = new LinkedHashSet<JwkDefinition>();
			Map<String, JwkMemberValue> attributes = new HashMap<String, JwkMemberValue>();

			while (parser.nextToken() == JsonToken.START_OBJECT) {
				while (parser.nextToken() == JsonToken.FIELD_NAME) {
					String attributeName = parser.getCurrentName();
					// gh-1082 - skip arrays such as x5c as we can't deal with them yet
					if (parser.nextToken() == JsonToken.START_ARRAY) {
						List<String> valueArray = new ArrayList<>();
						while (parser.nextToken() != JsonToken.END_ARRAY) {
							valueArray.add(parser.getValueAsString());
						}
						JwkMemberValue memberValue = new JwkMemberValue(valueArray);
						attributes.put(attributeName, memberValue);
					} else {
						attributes.put(attributeName, new JwkMemberValue(parser.getValueAsString()));
					}
				}
				JwkDefinition jwkDefinition = this.createJwkDefinition(attributes);
				if (!jwkDefinitions.add(jwkDefinition)) {
					throw new JwkException("Duplicate JWK found in Set: " +
							jwkDefinition.getKeyId() + " (" + KEY_ID + ")");
				}
				attributes.clear();
			}

		} catch (IOException ex) {
			throw new JwkException("An I/O error occurred while reading the JWK Set: " + ex.getMessage(), ex);
		} finally {
			try {
				if (parser != null) parser.close();
			} catch (IOException ex) { }
		}

		return jwkDefinitions;
	}

	/**
	 * Creates a {@link JwkDefinition} based on the supplied attributes.
	 *
	 * @param attributes the attributes used to create the {@link JwkDefinition}
	 * @return a {@link JwkDefinition}
	 * @throws JwkException if the Key Type (&quot;kty&quot;) attribute value is not {@link JwkDefinition.KeyType#RSA}
	 */
	private JwkDefinition createJwkDefinition(Map<String, JwkMemberValue> attributes) {
		JwkDefinition.KeyType keyType =
				JwkDefinition.KeyType.fromValue(attributes.get(KEY_TYPE).getStringValue());

		if (!JwkDefinition.KeyType.RSA.equals(keyType)) {
			throw new JwkException((keyType != null ? keyType.value() : "unknown") +
					" (" + KEY_TYPE + ") is currently not supported." +
					" Valid values for '" + KEY_TYPE + "' are: " + JwkDefinition.KeyType.RSA.value());
		}

		return this.createRsaJwkDefinition(attributes);
	}

	/**
	 * Creates a {@link RsaJwkDefinition} based on the supplied attributes.
	 *
	 * @param attributes the attributes used to create the {@link RsaJwkDefinition}
	 * @return a {@link JwkDefinition} representation of a RSA Key
	 * @throws JwkException if at least one attribute value is missing or invalid for a RSA Key
	 */
	private JwkDefinition createRsaJwkDefinition(Map<String, JwkMemberValue> attributes) {
		// kid
		String keyId = attributes.get(KEY_ID).getStringValue();
		if (!StringUtils.hasText(keyId)) {
			throw new JwkException(KEY_ID + " is a required attribute for a JWK.");
		}

		// x5c
		List<String> certificateChain = attributes.get(X509_CERTIFICATE_CHAIN).getArrayValue();
		if(!certificateChain.isEmpty()) {
			CertificateFactory certFactory;
			try {
				certFactory = CertificateFactory.getInstance("X.509");
				for (String certificate : certificateChain) {
					byte[] decodedCert = Base64.decodeBase64(certificate);
					X509Certificate x509Certificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decodedCert));
					x509Certificate.getKeyUsage()
				}
			} catch (CertificateException e) {
				// this exception should not be thrown since every JVM should implement X.509
				throw new JwkException("X.509 certificate is currently not supported.");
			}
		}

		// use
		JwkDefinition.PublicKeyUse publicKeyUse =
				JwkDefinition.PublicKeyUse.fromValue(attributes.get(PUBLIC_KEY_USE).getStringValue());
		if (!JwkDefinition.PublicKeyUse.SIG.equals(publicKeyUse)) {
			throw new JwkException((publicKeyUse != null ? publicKeyUse.value() : "unknown") +
					" (" + PUBLIC_KEY_USE + ") is currently not supported.");
		}

		// alg
		JwkDefinition.CryptoAlgorithm algorithm =
				JwkDefinition.CryptoAlgorithm.fromHeaderParamValue(attributes.get(ALGORITHM).getStringValue());
		if (algorithm != null &&
				!JwkDefinition.CryptoAlgorithm.RS256.equals(algorithm) &&
				!JwkDefinition.CryptoAlgorithm.RS384.equals(algorithm) &&
				!JwkDefinition.CryptoAlgorithm.RS512.equals(algorithm)) {
			throw new JwkException(algorithm.standardName() + " (" + ALGORITHM + ") is currently not supported.");
		}

		// n
		String modulus = attributes.get(RSA_PUBLIC_KEY_MODULUS).getStringValue();
		if (!StringUtils.hasText(modulus)) {
			throw new JwkException(RSA_PUBLIC_KEY_MODULUS + " is a required attribute for a RSA JWK.");
		}

		// e
		String exponent = attributes.get(RSA_PUBLIC_KEY_EXPONENT).getStringValue();
		if (!StringUtils.hasText(exponent)) {
			throw new JwkException(RSA_PUBLIC_KEY_EXPONENT + " is a required attribute for a RSA JWK.");
		}


		RsaJwkDefinition jwkDefinition = new RsaJwkDefinition(
				keyId, publicKeyUse, algorithm, modulus, exponent);

		return jwkDefinition;
	}
}