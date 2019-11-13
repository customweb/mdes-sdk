package com.wallee.sdk.mdes.encryption;

import java.security.PrivateKey;
import java.security.PublicKey;


/**
 * {@link PrivateKey} provider based on its corresponding {@link PublicKey} fingerprint.
 */
@FunctionalInterface
public interface IPrivateKeyProvider {

	/**
	 * @param fingerprint fingerprint of the related {@link PublicKey}
	 * @return {@link PrivateKey}
	 */
	PrivateKey getPrivateKeyByFingerprint(String fingerprint);
}
