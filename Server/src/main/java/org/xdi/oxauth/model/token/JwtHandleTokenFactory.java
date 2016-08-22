package org.xdi.oxauth.model.token;

import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.xdi.model.AuthenticationScriptUsageType;
import org.xdi.model.custom.script.conf.CustomScriptConfiguration;
import org.xdi.oxauth.model.common.AuthorizationCode;
import org.xdi.oxauth.model.common.AuthorizationGrantType;
import org.xdi.oxauth.model.common.User;
import org.xdi.oxauth.model.config.ConfigurationFactory;
import org.xdi.oxauth.model.crypto.AbstractCryptoProvider;
import org.xdi.oxauth.model.crypto.CryptoProviderFactory;
import org.xdi.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.xdi.oxauth.model.exception.InvalidClaimException;
import org.xdi.oxauth.model.jwt.Jwt;
import org.xdi.oxauth.model.jwt.JwtClaimName;
import org.xdi.oxauth.model.jwt.JwtType;
import org.xdi.oxauth.model.registration.Client;
import org.xdi.oxauth.service.external.ExternalAuthenticationService;

import com.google.common.collect.Lists;

public class JwtHandleTokenFactory {

	public static String generateHandleToken(final Client client,
			final AuthorizationGrantType authorizationGrantType,
			final User user,
			final String nonce,
			final Date authenticationTime,
			final AuthorizationCode authorizationCode, 
			final Map<String, String> claims,
			final String acrValues) throws Exception {
		
        Jwt jwt = new Jwt();
        AbstractCryptoProvider cryptoProvider = CryptoProviderFactory.getCryptoProvider(ConfigurationFactory.instance().getConfiguration());

        // Header
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(ConfigurationFactory.instance().getConfiguration().getTokenSigningType());

        jwt.getHeader().setType(JwtType.JWT);
        jwt.getHeader().setAlgorithm(signatureAlgorithm);
        String keyId = cryptoProvider.getKeyId(ConfigurationFactory.instance().getWebKeys(), signatureAlgorithm);
        if (keyId != null) {
            jwt.getHeader().setKeyId(keyId);
        }

        // Claims
        jwt.getClaims().setIssuer(ConfigurationFactory.instance().getConfiguration().getIssuer());
        jwt.getClaims().setAudience(client.getClientId());

        int lifeTime = ConfigurationFactory.instance().getConfiguration().getIdTokenLifetime();
        Calendar calendar = Calendar.getInstance();
        Date issuedAt = calendar.getTime();
        calendar.add(Calendar.SECOND, lifeTime);
        Date expiration = calendar.getTime();

        jwt.getClaims().setExpirationTime(expiration);
        jwt.getClaims().setIssuedAt(issuedAt);

        if (authorizationGrantType != null && authorizationGrantType == AuthorizationGrantType.CLIENT_CREDENTIALS) {
        	jwt.getClaims().setClaim(JwtClaimName.SUBJECT_IDENTIFIER, client.getClientId());
        } else {
    		
    		Object attributeValue = null;
    		
			try {
				attributeValue = user.getAttribute(ConfigurationFactory.instance().getConfiguration().getOpenidSubAttribute(), true);
			} catch (InvalidClaimException e) {
				// Ignore exception
			}
			
    		if (attributeValue != null && attributeValue instanceof String) {
    			jwt.getClaims().setClaim(JwtClaimName.SUBJECT_IDENTIFIER, attributeValue.toString());
    		}
    		
    	}

        if (acrValues != null) {
            jwt.getClaims().setClaim(JwtClaimName.AUTHENTICATION_CONTEXT_CLASS_REFERENCE, acrValues);
            setAmrClaim(jwt, acrValues);
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
        jwt.getClaims().setClaim("oxValidationURI", ConfigurationFactory.instance().getConfiguration().getCheckSessionIFrame());
        jwt.getClaims().setClaim("oxOpenIDConnectVersion", ConfigurationFactory.instance().getConfiguration().getOxOpenIdConnectVersion());

        if (claims != null) {
            for (Iterator<String> it = claims.keySet().iterator(); it.hasNext(); ) {
                String key = it.next();
                String value = claims.get(key);
                jwt.getClaims().setClaim(key, value);
            }
        }

        final List<String> jwtAccessTokenClaimsSupported = ConfigurationFactory.instance().getConfiguration().getJwtAccessTokenClaimsSupported();
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
        String signature = cryptoProvider.sign(jwt.getSigningInput(), jwt.getHeader().getKeyId(), client.getClientSecret(), signatureAlgorithm);
        jwt.setEncodedSignature(signature);

        return jwt.toString();
	}
	
    private static void setAmrClaim(JsonWebResponse jwt, String acrValues) {
        List<String> amrList = Lists.newArrayList();

        CustomScriptConfiguration script = ExternalAuthenticationService.instance().getCustomScriptConfiguration(
                AuthenticationScriptUsageType.BOTH, acrValues);
        if (script != null) {
            amrList.add(Integer.toString(script.getLevel()));
        }

        jwt.getClaims().setClaim(JwtClaimName.AUTHENTICATION_METHOD_REFERENCES, amrList);
    }

	
}