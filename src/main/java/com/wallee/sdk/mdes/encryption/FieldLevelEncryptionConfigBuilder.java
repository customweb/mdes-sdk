package com.wallee.sdk.mdes.encryption;


import com.jayway.jsonpath.JsonPath;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig.FieldValueEncoding;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import static com.mastercard.developer.utils.EncodingUtils.encodeBytes;
import static com.mastercard.developer.utils.StringUtils.isNullOrEmpty;
import static java.security.spec.MGF1ParameterSpec.SHA256;
import static java.security.spec.MGF1ParameterSpec.SHA512;

/**
 * A builder class for {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig}.
 */
/**
 * @author rodriguez
 *
 */
public final class FieldLevelEncryptionConfigBuilder {

    private Certificate encryptionCertificate;
    private String encryptionCertificateFingerprint;
    private String encryptionKeyFingerprint;
    private Map<String, String> encryptionPaths = new HashMap<>();
    private Map<String, String> decryptionPaths = new HashMap<>();
    private String oaepPaddingDigestAlgorithm;
    private String ivFieldName;
    private String ivHeaderName;
    private String oaepPaddingDigestAlgorithmFieldName;
    private String oaepPaddingDigestAlgorithmHeaderName;
    private String encryptedKeyFieldName;
    private String encryptedKeyHeaderName;
    private String encryptedValueFieldName;
    private String encryptionCertificateFingerprintFieldName;
    private String encryptionCertificateFingerprintHeaderName;
    private String encryptionKeyFingerprintFieldName;
    private String encryptionKeyFingerprintHeaderName;
    private FieldLevelEncryptionConfig.FieldValueEncoding fieldValueEncoding;
    private IPrivateKeyProvider decryptionPrivateKeyProvider;
    

    private FieldLevelEncryptionConfigBuilder() {
    }

    /**
     * Get an instance of the builder.
     * 
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public static FieldLevelEncryptionConfigBuilder aFieldLevelEncryptionConfig() {
        return new FieldLevelEncryptionConfigBuilder();
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionCertificate}.
     * @param encryptionCertificate encryption certificate
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionCertificate(Certificate encryptionCertificate) {
        this.encryptionCertificate = encryptionCertificate;
        return this;
    }
    
    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionCertificateFingerprint}.
     * 
     * @param encryptionCertificateFingerprint encryption certificate fingerprint
     * @return  {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionCertificateFingerprint(String encryptionCertificateFingerprint) {
        this.encryptionCertificateFingerprint = encryptionCertificateFingerprint;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionKeyFingerprint}.
     * 
     * @param encryptionCertificateFingerprint encryption certificate fingerprint
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionKeyFingerprint(String encryptionKeyFingerprint) {
        this.encryptionKeyFingerprint = encryptionKeyFingerprint;
        return this;
    }

    /**
     * Custom method
     * 
     * @param privateKeyProvider private key provider
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withDecryptionPrivateKeyProvider(IPrivateKeyProvider privateKeyProvider) {
        this.decryptionPrivateKeyProvider = privateKeyProvider;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionPaths}.
     * 
     * @param jsonPathIn json path in 
     * @param jsonPathOut json paht out
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionPath(String jsonPathIn, String jsonPathOut) {
        this.encryptionPaths.put(jsonPathIn, jsonPathOut);
        return this;
    }
 
    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#decryptionPaths}.
     * 
     * @param jsonPathIn json path in
     * @param jsonPathOut json path out
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withDecryptionPath(String jsonPathIn, String jsonPathOut) {
        this.decryptionPaths.put(jsonPathIn, jsonPathOut);
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#oaepPaddingDigestAlgorithm}.
     * 
     * @param oaepPaddingDigestAlgorithm oaep padding digest algorithm
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withOaepPaddingDigestAlgorithm(String oaepPaddingDigestAlgorithm) {
        this.oaepPaddingDigestAlgorithm = oaepPaddingDigestAlgorithm;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#ivFieldName}.
     * 
     * @param ivFieldName iv field name
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withIvFieldName(String ivFieldName) {
        this.ivFieldName = ivFieldName;
        return this;
    }
 
    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#oaepPaddingDigestAlgorithmFieldName}.
     *  
     * @param oaepPaddingDigestAlgorithmFieldName oaep padding digest algorithm field name
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withOaepPaddingDigestAlgorithmFieldName(String oaepPaddingDigestAlgorithmFieldName) {
        this.oaepPaddingDigestAlgorithmFieldName = oaepPaddingDigestAlgorithmFieldName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptedKeyFieldName}.
     * 
     * @param encryptedKeyFieldName encryption key fieldname
     * @return  {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withEncryptedKeyFieldName(String encryptedKeyFieldName) {
        this.encryptedKeyFieldName = encryptedKeyFieldName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptedValueFieldName}.
     * 
     * @param encryptedValueFieldName encryption value field name
     * @return  {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withEncryptedValueFieldName(String encryptedValueFieldName) {
        this.encryptedValueFieldName = encryptedValueFieldName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionCertificateFingerprintFieldName}.
     * 
     * @param encryptionCertificateFingerprintFieldName encryption certificate fingerprint fieldname
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionCertificateFingerprintFieldName(String encryptionCertificateFingerprintFieldName) {
        this.encryptionCertificateFingerprintFieldName = encryptionCertificateFingerprintFieldName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionKeyFingerprintFieldName}.
     * 
     * @param encryptionKeyFingerprintFieldName encryption key fingerprint fieldname
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionKeyFingerprintFieldName(String encryptionKeyFingerprintFieldName) {
        this.encryptionKeyFingerprintFieldName = encryptionKeyFingerprintFieldName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#fieldValueEncoding}.
     * 
     * @param fieldValueEncoding field value encoding
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withFieldValueEncoding(FieldValueEncoding fieldValueEncoding) {
        this.fieldValueEncoding = fieldValueEncoding;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#ivHeaderName}.
     * 
     * @param ivHeaderName iv header name
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withIvHeaderName(String ivHeaderName) {
        this.ivHeaderName = ivHeaderName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#oaepPaddingDigestAlgorithmHeaderName}.
     * 
     * @param oaepPaddingDigestAlgorithmHeaderName oeape padding digest algorithm header name
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withOaepPaddingDigestAlgorithmHeaderName(String oaepPaddingDigestAlgorithmHeaderName) {
        this.oaepPaddingDigestAlgorithmHeaderName = oaepPaddingDigestAlgorithmHeaderName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptedKeyHeaderName}.
     * 
     * @param encryptedKeyHeaderName  encryption key header name
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withEncryptedKeyHeaderName(String encryptedKeyHeaderName) {
        this.encryptedKeyHeaderName = encryptedKeyHeaderName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionCertificateFingerprintHeaderName}.
     * 
     * @param encryptionCertificateFingerprintHeaderName encryption certificate fingerprint header name
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionCertificateFingerprintHeaderName(String encryptionCertificateFingerprintHeaderName) {
        this.encryptionCertificateFingerprintHeaderName = encryptionCertificateFingerprintHeaderName;
        return this;
    }

    /**
     * See: {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig#encryptionKeyFingerprintHeaderName}.
     * 
     * @param encryptionKeyFingerprintHeaderName encrytion key fingerprint header name
     * @return {@link FieldLevelEncryptionConfigBuilder}
     */
    public FieldLevelEncryptionConfigBuilder withEncryptionKeyFingerprintHeaderName(String encryptionKeyFingerprintHeaderName) {
        this.encryptionKeyFingerprintHeaderName = encryptionKeyFingerprintHeaderName;
        return this;
    }

    /**
     * Build a {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig}.
     * 
     * @return{@link FieldLevelEncryptionConfigBuilder}
     * @throws EncryptionException encryption exception
     */
    public FieldLevelEncryptionConfig build() throws EncryptionException {

        checkJsonPathParameterValues();
        checkParameterValues();
        checkParameterConsistency();

        computeEncryptionCertificateFingerprintWhenNeeded();
        computeEncryptionKeyFingerprintWhenNeeded();

        FieldLevelEncryptionConfig config = new FieldLevelEncryptionConfig();
        config.setEncryptionCertificateFingerprintFieldName(encryptionCertificateFingerprintFieldName);
        config.setEncryptionKeyFingerprintFieldName(encryptionKeyFingerprintFieldName);
        config.setEncryptionCertificateFingerprint(encryptionCertificateFingerprint);
        config.setEncryptionKeyFingerprint(encryptionKeyFingerprint);
        config.setDecryptionPrivateKeyProvider(decryptionPrivateKeyProvider);
        config.setEncryptionPaths(encryptionPaths);
        config.setEncryptionCertificate(encryptionCertificate);
        config.setOaepPaddingDigestAlgorithm(oaepPaddingDigestAlgorithm);
        config.setIvFieldName(ivFieldName);
        config.setOaepPaddingDigestAlgorithmFieldName(oaepPaddingDigestAlgorithmFieldName);
        config.setDecryptionPaths(decryptionPaths);
        config.setEncryptedKeyFieldName(encryptedKeyFieldName);
        config.setFieldValueEncoding(fieldValueEncoding);
        config.setEncryptedValueFieldName(encryptedValueFieldName);
        config.setIvHeaderName(ivHeaderName);
        config.setOaepPaddingDigestAlgorithmHeaderName(oaepPaddingDigestAlgorithmHeaderName);
        config.setEncryptedKeyHeaderName(encryptedKeyHeaderName);
        config.setEncryptionCertificateFingerprintHeaderName(encryptionCertificateFingerprintHeaderName);
        config.setEncryptionKeyFingerprintHeaderName(encryptionKeyFingerprintHeaderName);
        return config;
    }

    private void checkJsonPathParameterValues() {
        for (Entry<String, String> entry : decryptionPaths.entrySet()) {
            if (!JsonPath.isPathDefinite(entry.getKey()) || !JsonPath.isPathDefinite(entry.getValue())) {
                throw new IllegalArgumentException("JSON paths for decryption must point to a single item!");
            }
        }

        for (Entry<String, String> entry : encryptionPaths.entrySet()) {
            if (!JsonPath.isPathDefinite(entry.getKey()) || !JsonPath.isPathDefinite(entry.getValue())) {
                throw new IllegalArgumentException("JSON paths for encryption must point to a single item!");
            }
        }
    }

    private void checkParameterValues() {
        if (oaepPaddingDigestAlgorithm == null) {
            throw new IllegalArgumentException("The digest algorithm for OAEP cannot be null!");
        }

        if (!SHA256.getDigestAlgorithm().equals(oaepPaddingDigestAlgorithm)
                && !SHA512.getDigestAlgorithm().equals(oaepPaddingDigestAlgorithm)) {
            throw new IllegalArgumentException(String.format("Unsupported OAEP digest algorithm: %s!", oaepPaddingDigestAlgorithm));
        }

        if (fieldValueEncoding == null) {
            throw new IllegalArgumentException("Value encoding for fields and headers cannot be null!");
        }

        if (ivFieldName == null && ivHeaderName == null) {
            throw new IllegalArgumentException("At least one of IV field name or IV header name must be set!");
        }

        if (encryptedKeyFieldName == null && encryptedKeyHeaderName == null) {
            throw new IllegalArgumentException("At least one of encrypted key field name or encrypted key header name must be set!");
        }

        if (encryptedValueFieldName == null) {
            throw new IllegalArgumentException("Encrypted value field name cannot be null!");
        }
    }

    private void checkParameterConsistency () {
        if (!decryptionPaths.isEmpty() && decryptionPrivateKeyProvider == null) {
            throw new IllegalArgumentException("Can't decrypt without decryption key!");
        }

        if (!encryptionPaths.isEmpty() && encryptionCertificate == null) {
            throw new IllegalArgumentException("Can't encrypt without encryption key!");
        }

        if (ivHeaderName != null && encryptedKeyHeaderName == null
                || ivHeaderName == null && encryptedKeyHeaderName != null) {
            throw new IllegalArgumentException("IV header name and encrypted key header name must be both set or both unset!");
        }

        if (ivFieldName != null && encryptedKeyFieldName == null
                || ivFieldName == null && encryptedKeyFieldName != null) {
            throw new IllegalArgumentException("IV field name and encrypted key field name must be both set or both unset!");
        }
    }

    private void computeEncryptionCertificateFingerprintWhenNeeded() throws EncryptionException {
        try {
            if (encryptionCertificate == null || !isNullOrEmpty(encryptionCertificateFingerprint)) {
                // No encryption certificate set or certificate fingerprint already provided
                return;
            }
            byte[] certificateFingerprintBytes = sha256digestBytes(encryptionCertificate.getEncoded());
            encryptionCertificateFingerprint = encodeBytes(certificateFingerprintBytes, FieldValueEncoding.HEX);
        } catch (Exception e) {
            throw new EncryptionException("Failed to compute encryption certificate fingerprint!", e);
        }
    }

    private void computeEncryptionKeyFingerprintWhenNeeded() throws EncryptionException {
        try {
            if (encryptionCertificate == null || !isNullOrEmpty(encryptionKeyFingerprint)) {
                // No encryption certificate set or key fingerprint already provided
                return;
            }
            byte[] keyFingerprintBytes = sha256digestBytes(encryptionCertificate.getPublicKey().getEncoded());
            encryptionKeyFingerprint = encodeBytes(keyFingerprintBytes, FieldValueEncoding.HEX);
        } catch (Exception e) {
            throw new EncryptionException("Failed to compute encryption key fingerprint!", e);
        }
    }

    private static byte[] sha256digestBytes(byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(bytes);
        return messageDigest.digest();
    }
}
