/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.crypto.signature;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.xdi.oxauth.model.exception.SignatureException;

public class BouncyCastleSignatureVerification implements SignatureVerification {

    @Override
    public boolean checkSignature(X509Certificate certificate, byte[] signedBytes, byte[] signature) throws SignatureException {
        return checkSignature(certificate.getPublicKey(), signedBytes, signature);
    }

    @Override
    public boolean checkSignature(PublicKey publicKey, byte[] signedBytes, byte[] signature) throws SignatureException {
        boolean isValid = false;
		try {
			Signature ecdsaSignature = Signature.getInstance("SHA256WITHECDSA");
			ecdsaSignature.initVerify(publicKey);
			ecdsaSignature.update(signedBytes);

			isValid = ecdsaSignature.verify(signature);
		} catch (GeneralSecurityException ex) {
			throw new SignatureException(ex);
		}
        
        return isValid;
    }

    @Override
    public PublicKey decodePublicKey(byte[] encodedPublicKey) throws SignatureException {
            X9ECParameters curve = SECNamedCurves.getByName("SECP256R1");
            ECPoint point = curve.getCurve().decodePoint(encodedPublicKey);

            try {
				return KeyFactory.getInstance("ECDSA").generatePublic(
				        new ECPublicKeySpec(point,
				                new ECParameterSpec(
				                        curve.getCurve(),
				                        curve.getG(),
				                        curve.getN(),
				                        curve.getH()
				                )
				        )
				);
			} catch (GeneralSecurityException ex) {
				throw new SignatureException(ex);
			}
    }

    @Override
    public byte[] hash(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] hash(String str) {
        return hash(str.getBytes());
    }
}
