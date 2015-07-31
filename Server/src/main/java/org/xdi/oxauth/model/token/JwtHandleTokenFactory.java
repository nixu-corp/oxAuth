package org.xdi.oxauth.model.token;

import java.security.SignatureException;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.xdi.oxauth.model.common.AuthorizationCode;
import org.xdi.oxauth.model.common.AuthorizationGrantType;
import org.xdi.oxauth.model.common.User;
import org.xdi.oxauth.model.config.ConfigurationFactory;
import org.xdi.oxauth.model.crypto.signature.ECDSAPrivateKey;
import org.xdi.oxauth.model.crypto.signature.RSAPrivateKey;
import org.xdi.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.xdi.oxauth.model.exception.InvalidClaimException;
import org.xdi.oxauth.model.exception.InvalidJwtException;
import org.xdi.oxauth.model.jwk.JSONWebKey;
import org.xdi.oxauth.model.jwk.JSONWebKeySet;
import org.xdi.oxauth.model.jws.ECDSASigner;
import org.xdi.oxauth.model.jws.HMACSigner;
import org.xdi.oxauth.model.jws.RSASigner;
import org.xdi.oxauth.model.jwt.Jwt;
import org.xdi.oxauth.model.jwt.JwtClaimName;
import org.xdi.oxauth.model.jwt.JwtHeaderName;
import org.xdi.oxauth.model.jwt.JwtType;
import org.xdi.oxauth.model.registration.Client;
import org.xdi.util.security.StringEncrypter;

public class JwtHandleTokenFactory {

	public static String generateHandleToken(final Client client,
			final AuthorizationGrantType authorizationGrantType,
			final User user,
			final String nonce,
			final Date authenticationTime,
			final AuthorizationCode authorizationCode, 
			final Map<String, String> claims) throws SignatureException, InvalidJwtException, StringEncrypter.EncryptionException {
		
        Jwt jwt = new Jwt();
        JSONWebKeySet jwks = ConfigurationFactory.getWebKeys();

        // Header
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromName(ConfigurationFactory.getConfiguration().getTokenSigningType());

        jwt.getHeader().setType(JwtType.JWS);
        jwt.getHeader().setAlgorithm(signatureAlgorithm);
        List<JSONWebKey> jsonWebKeys = jwks.getKeys(signatureAlgorithm);
        if (jsonWebKeys.size() > 0) {
            jwt.getHeader().setKeyId(jsonWebKeys.get(0).getKeyId());
        }

        // Claims
        jwt.getClaims().setIssuer(ConfigurationFactory.getConfiguration().getIssuer());
        jwt.getClaims().setAudience(client.getClientId());

        int lifeTime = ConfigurationFactory.getConfiguration().getIdTokenLifetime();
        Calendar calendar = Calendar.getInstance();
        Date issuedAt = calendar.getTime();
        calendar.add(Calendar.SECOND, lifeTime);
        Date expiration = calendar.getTime();

        jwt.getClaims().setExpirationTime(expiration);
        jwt.getClaims().setIssuedAt(issuedAt);

        if (authorizationGrantType != null && authorizationGrantType == AuthorizationGrantType.CLIENT_CREDENTIALS) {
        	jwt.getClaims().setClaim(JwtClaimName.SUBJECT_IDENTIFIER, client.getClientId());
        } else if (ConfigurationFactory.getConfiguration().getSubjectClaim() != null && user != null) {
    		
    		Object attributeValue = null;
    		
			try {
				attributeValue = user.getAttribute(ConfigurationFactory.getConfiguration().getSubjectClaim(), true);
			} catch (InvalidClaimException e) {
				// Ignore exception
			}
			
    		if (attributeValue != null && attributeValue instanceof String) {
    			jwt.getClaims().setClaim(JwtClaimName.SUBJECT_IDENTIFIER, attributeValue.toString());
    		}
    		
    	} else {
    		jwt.getClaims().setClaim(JwtClaimName.SUBJECT_IDENTIFIER, client.getSubjectIdentifier());
    	}

        if (StringUtils.isNotBlank(nonce)) {
            jwt.getClaims().setClaim(JwtClaimName.NONCE, nonce);
        }
        if (authenticationTime != null) {
            jwt.getClaims().setClaim(JwtClaimName.AUTHENTICATION_TIME, authenticationTime);
        }
        if (authorizationCode != null) {
            String codeHash = authorizationCode.getHash(signatureAlgorithm);
            jwt.getClaims().setClaim(JwtClaimName.CODE_HASH, codeHash);
        }
        jwt.getClaims().setClaim("oxValidationURI", ConfigurationFactory.getConfiguration().getCheckSessionIFrame());
        jwt.getClaims().setClaim("oxOpenIDConnectVersion", ConfigurationFactory.getConfiguration().getOxOpenIdConnectVersion());

        if (claims != null) {
            for (Iterator<String> it = claims.keySet().iterator(); it.hasNext(); ) {
                String key = it.next();
                String value = claims.get(key);
                jwt.getClaims().setClaim(key, value);
            }
        }

        final List<String> jwtAccessTokenClaimsSupported = ConfigurationFactory.getConfiguration().getJwtAccessTokenClaimsSupported();
        if (jwtAccessTokenClaimsSupported != null) {
        	
        	for (String claim : jwtAccessTokenClaimsSupported) {
        		
        		final List<String> claimValues = user.getAttributeValues(claim);
        		if (claimValues != null && claimValues.size() > 0) {
        			if (claimValues.size() == 1) {
        				jwt.getClaims().setClaim(claim, claimValues.get(0));
        			} else {
        				jwt.getClaims().setClaim(claim, claimValues);
        			}
        		}
        		
        	}
        	
        }
        
        // Signature
        JSONWebKey jwk = null;
        switch (signatureAlgorithm) {
            case HS256:
            case HS384:
            case HS512:
                HMACSigner hmacSigner = new HMACSigner(signatureAlgorithm, ConfigurationFactory.getConfiguration().getTokenSigningKey());
                jwt = hmacSigner.sign(jwt);
                break;
            case RS256:
            case RS384:
            case RS512:
                jwk = jwks.getKey(jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
                RSAPrivateKey rsaPrivateKey = new RSAPrivateKey(
                        jwk.getPrivateKey().getModulus(),
                        jwk.getPrivateKey().getPrivateExponent());
                RSASigner rsaSigner = new RSASigner(signatureAlgorithm, rsaPrivateKey);
                jwt = rsaSigner.sign(jwt);
                break;
            case ES256:
            case ES384:
            case ES512:
                jwk = jwks.getKey(jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
                ECDSAPrivateKey ecdsaPrivateKey = new ECDSAPrivateKey(jwk.getPrivateKey().getD());
                ECDSASigner ecdsaSigner = new ECDSASigner(signatureAlgorithm, ecdsaPrivateKey);
                jwt = ecdsaSigner.sign(jwt);
                break;
            case NONE:
                break;
            default:
                break;
        }

        return jwt.toString();
	}
	
}
