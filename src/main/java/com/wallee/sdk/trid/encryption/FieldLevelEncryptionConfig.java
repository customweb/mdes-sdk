package com.wallee.sdk.trid.encryption;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Map;


/**
 * A POJO for storing the encryption/decryption configuration.
 */
public class FieldLevelEncryptionConfig extends com.mastercard.developer.encryption.FieldLevelEncryptionConfig {

	protected IPrivateKeyProvider decryptionPrivateKeyProvider;

	protected FieldLevelEncryptionConfig() {
    	super();
    }

    protected Certificate getEncryptionCertificate() {
    	return encryptionCertificate;
    }
    
    protected PrivateKey getDecryptionKey(String fingerprint) {
    	return decryptionPrivateKeyProvider.getPrivateKeyByFingerprint(fingerprint);
    }

    protected String getOaepPaddingDigestAlgorithm() {
    	return oaepPaddingDigestAlgorithm;
    }
    
    protected FieldValueEncoding getFieldValueEncoding() {
    	return fieldValueEncoding;
    }

    protected  Map<String, String> getEncryptionPaths() {
    	return encryptionPaths;
    }
    
    protected Map<String, String>  getDecryptionPaths() {
    	return decryptionPaths;
    }
    
	protected void setDecryptionPrivateKeyProvider(IPrivateKeyProvider decryptionPrivateKeyProvider) {
		this.decryptionPrivateKeyProvider = decryptionPrivateKeyProvider;
	}


	protected void setEncryptionCertificate(Certificate encryptionCertificate) {
		this.encryptionCertificate = encryptionCertificate;
	}


	protected void setEncryptionCertificateFingerprint(String encryptionCertificateFingerprint) {
		this.encryptionCertificateFingerprint = encryptionCertificateFingerprint;
	}


	protected void setEncryptionKeyFingerprint(String encryptionKeyFingerprint) {
		this.encryptionKeyFingerprint = encryptionKeyFingerprint;
	}

	protected void setEncryptionPaths(Map<String, String> encryptionPaths) {
		this.encryptionPaths = encryptionPaths;
	}


	protected void setDecryptionPaths(Map<String, String> decryptionPaths) {
		this.decryptionPaths = decryptionPaths;
	}


	protected void setOaepPaddingDigestAlgorithm(String oaepPaddingDigestAlgorithm) {
		this.oaepPaddingDigestAlgorithm = oaepPaddingDigestAlgorithm;
	}


	protected void setOaepPaddingDigestAlgorithmFieldName(String oaepPaddingDigestAlgorithmFieldName) {
		this.oaepPaddingDigestAlgorithmFieldName = oaepPaddingDigestAlgorithmFieldName;
	}


	protected void setOaepPaddingDigestAlgorithmHeaderName(String oaepPaddingDigestAlgorithmHeaderName) {
		this.oaepPaddingDigestAlgorithmHeaderName = oaepPaddingDigestAlgorithmHeaderName;
	}


	protected void setIvFieldName(String ivFieldName) {
		this.ivFieldName = ivFieldName;
	}


	protected void setIvHeaderName(String ivHeaderName) {
		this.ivHeaderName = ivHeaderName;
	}

	protected void setEncryptedKeyFieldName(String encryptedKeyFieldName) {
		this.encryptedKeyFieldName = encryptedKeyFieldName;
	}

	protected void setEncryptedKeyHeaderName(String encryptedKeyHeaderName) {
		this.encryptedKeyHeaderName = encryptedKeyHeaderName;
	}

	protected void setEncryptedValueFieldName(String encryptedValueFieldName) {
		this.encryptedValueFieldName = encryptedValueFieldName;
	}

	protected void setEncryptionCertificateFingerprintFieldName(String encryptionCertificateFingerprintFieldName) {
		this.encryptionCertificateFingerprintFieldName = encryptionCertificateFingerprintFieldName;
	}

	protected void setEncryptionCertificateFingerprintHeaderName(String encryptionCertificateFingerprintHeaderName) {
		this.encryptionCertificateFingerprintHeaderName = encryptionCertificateFingerprintHeaderName;
	}

	protected void setEncryptionKeyFingerprintFieldName(String encryptionKeyFingerprintFieldName) {
		this.encryptionKeyFingerprintFieldName = encryptionKeyFingerprintFieldName;
	}

	protected void setEncryptionKeyFingerprintHeaderName(String encryptionKeyFingerprintHeaderName) {
		this.encryptionKeyFingerprintHeaderName = encryptionKeyFingerprintHeaderName;
	}

	protected void setFieldValueEncoding(FieldValueEncoding fieldValueEncoding) {
		this.fieldValueEncoding = fieldValueEncoding;
	}

	protected IPrivateKeyProvider getDecryptionPrivateKeyProvider() {
		return decryptionPrivateKeyProvider;
	}

	protected String getOaepPaddingDigestAlgorithmFieldName() {
		return oaepPaddingDigestAlgorithmFieldName;
	}

	protected String getIvFieldName() {
		return ivFieldName;
	}

	protected String getEncryptedKeyFieldName() {
		return encryptedKeyFieldName;
	}

	protected String getEncryptedValueFieldName() {
		return encryptedValueFieldName;
	}

	protected String getEncryptionCertificateFingerprintFieldName() {
		return encryptionCertificateFingerprintFieldName;
	}

	protected String getEncryptionKeyFingerprintFieldName() {
		return encryptionKeyFingerprintFieldName;
	}
    
}
