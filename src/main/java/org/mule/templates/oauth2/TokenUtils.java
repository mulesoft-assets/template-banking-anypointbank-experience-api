/**
 * Mule Anypoint Template
 * Copyright (c) MuleSoft, Inc.
 * All rights reserved.  http://www.mulesoft.com
 */
package org.mule.templates.oauth2;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;

import java.util.Map;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;

/**
 * Utility class for token operations
 */

public class TokenUtils {

	
	/**
	 *	Built JWT token
	 * 
	 * @param id
	 * @param ssn
	 * @param issuer
	 * @param minutes
	 * @param aesKeyString
	 * @return access token
	 */
	public static String getCompactSerialization(String id, String ssn, String issuer, Integer minutes,
			String aesKeyString) {

		try {
			JwtClaims claims = new JwtClaims();
			claims.setIssuer(issuer);
			claims.setExpirationTimeMinutesInTheFuture(minutes);
			claims.setIssuedAtToNow();
			claims.setSubject(id);
			claims.setClaim("ssn", ssn);

			OctetSequenceJsonWebKey aesKey = (OctetSequenceJsonWebKey) JsonWebKey.Factory.newJwk(aesKeyString);
			JsonWebEncryption jwe = new JsonWebEncryption();

			// header + settings
			jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
			jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);
			jwe.setPayload(claims.toJson());
			jwe.setKey(aesKey.getKey());
			return jwe.getCompactSerialization();

		} catch (JoseException e) {
			throw new RuntimeException("Error: " + e.getMessage());
		}
	}

	/**
	 * Retrieve JWT claims from uiToken
	 * 
	 * @param uiToken
	 * @param issuer
	 * @param aesKeyString
	 * @return JWT claims
	 */
	public static Map<String, Object> getJwtClaims(String uiToken, String issuer, String aesKeyString)
			throws InvalidJwtException, JoseException {

		try {
			OctetSequenceJsonWebKey aesKey = (OctetSequenceJsonWebKey) JsonWebKey.Factory.newJwk(aesKeyString);

			JwtConsumer jwtConsumer = new JwtConsumerBuilder().setDisableRequireSignature().setRequireExpirationTime()
					.setJweAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.WHITELIST, "dir"))
					.setMaxFutureValidityInMinutes(360).setExpectedIssuer(issuer).setDecryptionKey(aesKey.getKey())
					.build();

			JwtClaims jwtClaims = jwtConsumer.processToClaims(uiToken);
			return jwtClaims.getClaimsMap();

		} catch (JoseException | InvalidJwtException e) {
			throw new RuntimeException("Error retrieving claims from token: " + e.getMessage());
		}
	}
}