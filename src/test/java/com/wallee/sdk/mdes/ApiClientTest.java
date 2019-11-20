package com.wallee.sdk.mdes;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.gson.reflect.TypeToken;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.utils.EncryptionUtils;
import com.wallee.sdk.mdes.ApiClient.ApiClientConfiguration;
import com.wallee.sdk.mdes.api.DeleteApi;
import com.wallee.sdk.mdes.api.GetAssetApi;
import com.wallee.sdk.mdes.api.GetDigitalAssetsApi;
import com.wallee.sdk.mdes.api.GetTaskStatusApi;
import com.wallee.sdk.mdes.api.GetTokenApi;
import com.wallee.sdk.mdes.api.SearchTokensApi;
import com.wallee.sdk.mdes.api.TokenizeApi;
import com.wallee.sdk.mdes.api.TransactApi;
import com.wallee.sdk.mdes.encryption.FieldLevelEncryptionConfig;
import com.wallee.sdk.mdes.encryption.FieldLevelEncryptionConfigBuilder;
import com.wallee.sdk.mdes.model.AccountHolderData;
import com.wallee.sdk.mdes.model.AssetResponseSchema;
import com.wallee.sdk.mdes.model.BillingAddress;
import com.wallee.sdk.mdes.model.CardAccountDataInbound;
import com.wallee.sdk.mdes.model.DeleteRequestSchema;
import com.wallee.sdk.mdes.model.DeleteResponseSchema;
import com.wallee.sdk.mdes.model.ErrorsResponse;
import com.wallee.sdk.mdes.model.FundingAccountData;
import com.wallee.sdk.mdes.model.FundingAccountInfo;
import com.wallee.sdk.mdes.model.FundingAccountInfoEncryptedPayload;
import com.wallee.sdk.mdes.model.GetDigitalAssetsEncryptedData;
import com.wallee.sdk.mdes.model.GetDigitalAssetsRequestSchema;
import com.wallee.sdk.mdes.model.GetDigitalAssetsRequestSchemaEncryptedPayload;
import com.wallee.sdk.mdes.model.GetDigitalAssetsResponseSchema;
import com.wallee.sdk.mdes.model.GetTaskStatusRequestSchema;
import com.wallee.sdk.mdes.model.GetTaskStatusResponseSchema;
import com.wallee.sdk.mdes.model.GetTokenRequestSchema;
import com.wallee.sdk.mdes.model.GetTokenResponseSchema;
import com.wallee.sdk.mdes.model.SearchTokensRequestSchema;
import com.wallee.sdk.mdes.model.SearchTokensResponseSchema;
import com.wallee.sdk.mdes.model.TokenizeRequestSchema;
import com.wallee.sdk.mdes.model.TokenizeResponseSchema;
import com.wallee.sdk.mdes.model.TransactRequestSchema;
import com.wallee.sdk.mdes.model.TransactResponseSchema;
public class ApiClientTest {

	private static String signingKeyAlias;
	private static String signingKeyPassword;
	private static String consumerKey;

	private static PrivateKey signingKey;
	private static PrivateKey decryptionPrivateKey;
	private static Certificate publicKeyEncryptionCertificate;
	private static String encodedBase64PublicKey;
	private static String encodedBase64SigningKey;

	@BeforeClass
	public static void loadKeys() throws IOException, GeneralSecurityException {

		loadEnviromentVariables();
		
		// public key
		String decodedPublicKeyStr = new String(Base64.getDecoder().decode(encodedBase64PublicKey.getBytes(StandardCharsets.UTF_8)),
				StandardCharsets.UTF_8);
		try (InputStream in = new ByteArrayInputStream(decodedPublicKeyStr.getBytes(StandardCharsets.UTF_8))) {
			publicKeyEncryptionCertificate = loadEncryptionCertificate(in);
		}

		// private key
		decryptionPrivateKey = EncryptionUtils.loadDecryptionKey("./src/test/resources/private-key-decrypt.pem");

		// signing key	
		byte[] decodeP12 = Base64.getDecoder().decode(encodedBase64SigningKey.getBytes(StandardCharsets.UTF_8));

		signingKey = loadSigningKey(//
				decodeP12, // 
				signingKeyAlias, //
				signingKeyPassword);
	}

	private static void loadEnviromentVariables() throws GeneralSecurityException, IOException {
		signingKeyAlias = Optional//
				.ofNullable(System.getenv("MDES_SIGNING_KEY_ALIAS"))//
				.orElseThrow(() -> new NullPointerException("MDES_SIGNING_KEY_ALIAS"));
		
		signingKeyPassword = Optional//
				.ofNullable(System.getenv("MDES_SIGNING_KEY_PASSWORD"))//
				.orElseThrow(() -> new NullPointerException("MDES_SIGNING_KEY_PASSWORD"));
		
		consumerKey = Optional//
				.ofNullable(System.getenv("MDES_CONSUMER_KEY"))//
				.orElseThrow(() -> new NullPointerException("MDES_CONSUMER_KEY"));
		
		encodedBase64PublicKey = Optional//
				.ofNullable(System.getenv("MDES_ENCODED_BASE64_PUBLIC_KEY"))//
				.orElseThrow(() -> new NullPointerException("MDES_ENCODED_BASE64_PUBLIC_KEY"));
		
		encodedBase64SigningKey = Optional//
				.ofNullable(System.getenv("MDES_ENCODED_BASE64_SIGNING_KEY"))//
				.orElseThrow(() -> new NullPointerException("MDES_ENCODED_BASE64_SIGNING_KEY"));
	}
	/*
	 * Overloaded version with input parameter InputStream instead of String (path) of:
	 * com.mastercard.developer.utils.EncryptionUtils.loadEncryptionCertificate(String)
	 */
	private static Certificate loadEncryptionCertificate(InputStream inStream)
			throws CertificateException, NoSuchProviderException {
		CertificateFactory factory = CertificateFactory.getInstance("X.509", "SUN");
		return factory.generateCertificate(inStream);
	}

	/*
	 * Overloaded version with signing-key as byte array parameter instead of String (path) of:
	 * com.mastercard.developer.utils.AuthenticationUtils.loadSigningKey(String, String, String)
	 */
	private static PrivateKey loadSigningKey(byte[] pkcs12Key, String signingKeyAlias, String signingKeyPassword)
			throws IOException, NoSuchProviderException, KeyStoreException, CertificateException,
			NoSuchAlgorithmException, UnrecoverableKeyException {
		KeyStore pkcs12KeyStore = KeyStore.getInstance("PKCS12", "SunJSSE");

		try (InputStream in = new ByteArrayInputStream(pkcs12Key)) {
			pkcs12KeyStore.load(in, signingKeyPassword.toCharArray());
			return (PrivateKey) pkcs12KeyStore.getKey(signingKeyAlias, signingKeyPassword.toCharArray());
		}

	}
	
	private static FieldLevelEncryptionConfig buildFieldLevelEncryptionConfig(Certificate publicKeyEncryptionCertificate, PrivateKey decryptionPrivateKey) {
		try {
			return FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
				    .withEncryptionPath("$.fundingAccountInfo.encryptedPayload.encryptedData", "$.fundingAccountInfo.encryptedPayload")  
				    .withEncryptionPath("$.encryptedPayload.encryptedData", "$.encryptedPayload")
				    .withDecryptionPath("$.tokenDetail", "$.tokenDetail.encryptedData")
				    .withDecryptionPath("$.encryptedPayload", "$.encryptedPayload.encryptedData")
				    .withEncryptionCertificate(publicKeyEncryptionCertificate)
				    .withDecryptionPrivateKeyProvider((testFingerprint) -> {
				    	final String SANDBOX_FINGERPRINT = "3e3ff1c50fd4046b9a80c39d3d077f7313b92ea01462744bfe50b62769dbef68";
				    	if (SANDBOX_FINGERPRINT.equals(testFingerprint)) {
				    		return decryptionPrivateKey;
				    	}
				    	throw new RuntimeException("fingerprint: '" + testFingerprint + "' not found.");
				     })
				    .withOaepPaddingDigestAlgorithm("SHA-512")
				    .withEncryptedValueFieldName("encryptedData")
				    .withEncryptedKeyFieldName("encryptedKey")
				    .withIvFieldName("iv")
				    .withOaepPaddingDigestAlgorithmFieldName("oaepHashingAlgorithm")
				    .withEncryptionCertificateFingerprintFieldName("publicKeyFingerprint")
				    .withFieldValueEncoding(FieldLevelEncryptionConfig.FieldValueEncoding.HEX)
				    .build();
		} catch (EncryptionException e) {
			throw new RuntimeException(e);
		}
    }

	private ApiClient buildApiClient() {
		ApiClientConfiguration apiClientConfiguration = ApiClientConfiguration.building()//
				.setEndpoint(ApiClient.EndPoint.SANDBOX)//
				.setSigningKey(signingKey)//
				.setPublicKeyEncryptionCertificate(publicKeyEncryptionCertificate)//
				.setConsumerKey(consumerKey)//
				.setFieldLevelEncryptionConfig(buildFieldLevelEncryptionConfig(publicKeyEncryptionCertificate, decryptionPrivateKey))//
				.build();

		return new ApiClient(apiClientConfiguration);
	}
	
	@Test 
	public void tokenizeTest() throws ApiException {

		TokenizeRequestSchema tokenizeRequestSchema = new TokenizeRequestSchema();
		tokenizeRequestSchema.setResponseHost("site1.payment-app-provider.com");
		tokenizeRequestSchema.setRequestId("123456");
		tokenizeRequestSchema.setTokenType("CLOUD");
		tokenizeRequestSchema.setTokenRequestorId("98765432101");
		tokenizeRequestSchema.setTaskId("123456");
		tokenizeRequestSchema.setFundingAccountInfo(buildFundingAccountInfo());
		tokenizeRequestSchema.setConsumerLanguage("en");
		tokenizeRequestSchema.setTokenizationAuthenticationValue("RHVtbXkgYmFzZSA2NCBkYXRhIC0gdGhpcyBpcyBub3QgYSByZWFsIFRBViBleGFtcGxl"); 

		ApiClient apiClient = buildApiClient();

		TokenizeResponseSchema response = new TokenizeApi(apiClient).createTokenize(tokenizeRequestSchema);

		Assert.assertEquals("site.1.sample.service.mastercard.com", response.getResponseHost());
		Assert.assertEquals("123456", response.getResponseId());
		Assert.assertEquals("APPROVED", response.getDecision());
		Assert.assertEquals("DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45", response.getTokenUniqueReference());
		Assert.assertEquals("FWSPMC000000000159f71f703d2141efaf04dd26803f922b", response.getPanUniqueReference());
		
		
		Assert.assertEquals("12344", response.getAuthenticationMethods().get(0).getId());
		Assert.assertEquals("TEXT_TO_CARDHOLDER_NUMBER", response.getAuthenticationMethods().get(0).getType());
		Assert.assertEquals("12X-XXX-XX32", response.getAuthenticationMethods().get(0).getValue());

		Assert.assertEquals("12345", response.getAuthenticationMethods().get(1).getId());
		Assert.assertEquals("CARDHOLDER_TO_CALL_AUTOMATED_NUMBER", response.getAuthenticationMethods().get(1).getType());
		Assert.assertEquals("1-800-BANK-NUMBER", response.getAuthenticationMethods().get(1).getValue());
		
		Assert.assertEquals("800200c9-629d-11e3-949a-0739d27e5a66", response.getProductConfig().getBrandLogoAssetId());
		Assert.assertEquals(null, response.getProductConfig().getIssuerLogoAssetId());
		Assert.assertEquals(null, response.getProductConfig().getIsCoBranded());
		Assert.assertEquals(null, response.getProductConfig().getCoBrandName());
		Assert.assertEquals(null, response.getProductConfig().getCoBrandLogoAssetId());
		
		Assert.assertEquals("739d27e5-629d-11e3-949a-0800200c9a66", response.getProductConfig().getCardBackgroundCombinedAssetId());
		Assert.assertEquals(null, response.getProductConfig().getCardBackgroundAssetId());
		Assert.assertEquals(null, response.getProductConfig().getIconAssetId());
		Assert.assertEquals("000000", response.getProductConfig().getForegroundColor());
		Assert.assertEquals("Issuing Bank", response.getProductConfig().getIssuerName());
		Assert.assertEquals("Bank Rewards MasterCard", response.getProductConfig().getShortDescription());
		Assert.assertEquals("Bank Rewards MasterCard with the super duper rewards program", response.getProductConfig().getLongDescription());
		Assert.assertEquals("https://bank.com/customerservice", response.getProductConfig().getCustomerServiceUrl());
		Assert.assertEquals(null, response.getProductConfig().getCustomerServiceEmail());
		Assert.assertEquals(null, response.getProductConfig().getCustomerServicePhoneNumber());
		Assert.assertEquals(null, response.getProductConfig().getOnlineBankingLoginUrl());
		Assert.assertEquals("https://bank.com/termsAndConditions", response.getProductConfig().getTermsAndConditionsUrl());
		Assert.assertEquals("https://bank.com/privacy", response.getProductConfig().getPrivacyPolicyUrl());
		Assert.assertEquals("123456", response.getProductConfig().getIssuerProductConfigCode());
		
		Assert.assertEquals("1234", response.getTokenInfo().getTokenPanSuffix());
		Assert.assertEquals("2345", response.getTokenInfo().getAccountPanSuffix());
		Assert.assertNotNull(response.getTokenInfo().getTokenExpiry());
		Assert.assertEquals("0921", response.getTokenInfo().getAccountPanExpiry());
		Assert.assertEquals("false", response.getTokenInfo().getDsrpCapable());
		Assert.assertEquals("1", response.getTokenInfo().getTokenAssuranceLevel());
		Assert.assertEquals("CREDIT", response.getTokenInfo().getProductCategory());

		Assert.assertEquals("4c4ead5927f0df8117f178eea9308daa58e27abc", response.getTokenDetail().getTokenUniqueReference());
		Assert.assertEquals(null, response.getTokenDetail().getPublicKeyFingerprint());
		Assert.assertEquals(null, response.getTokenDetail().getEncryptedKey());
		Assert.assertEquals(null, response.getTokenDetail().getOaepHashingAlgorithm());
		Assert.assertEquals(null, response.getTokenDetail().getIv());

		Assert.assertEquals(null, response.getTokenDetail().getEncryptedData().getAccountHolderData());
		Assert.assertEquals("500181d9f8e0629211e3949a08002", response.getTokenDetail().getEncryptedData().getPaymentAccountReference());
		Assert.assertEquals(null, response.getTokenDetail().getEncryptedData().getCardAccountData());
	}

	private static FundingAccountInfo buildFundingAccountInfo() {
		return new FundingAccountInfo().encryptedPayload(buildFundingAccountInfoEncryptedPayload());
	}

	private static FundingAccountInfoEncryptedPayload buildFundingAccountInfoEncryptedPayload() {
		return new FundingAccountInfoEncryptedPayload().encryptedData(buildFundingAccountData());
	}

	private static FundingAccountData buildFundingAccountData() {
		return new FundingAccountData().accountHolderData(buildAccountHolderData()).source("ACCOUNT_ON_FILE")
				.cardAccountData(buildCardAccountDataInbound());
	}

	private static CardAccountDataInbound buildCardAccountDataInbound() {
		return new CardAccountDataInbound().accountNumber("5123456789012345").securityCode("123").expiryYear("21")
				.expiryMonth("09");
	}

	private static AccountHolderData buildAccountHolderData() {
		return new AccountHolderData().accountHolderAddress(buildBillingAddress()).accountHolderName("John Doe");
	}

	private static BillingAddress buildBillingAddress() {
		return new BillingAddress().line1("100 1st Street").line2("Apt. 4B").city("St. Louis").countrySubdivision("MO")
				.postalCode("61000").country("USA");
	}

	@Test
	public void getAssetTest() throws ApiException {
		ApiClient apiClient = buildApiClient();

		GetAssetApi getAssetApi = new GetAssetApi(apiClient);
		AssetResponseSchema response = getAssetApi.getAsset("3789637f-32a1-4810-a138-4bf34501c509");
		Assert.assertEquals("image/pdf", response.getMediaContents().get(0).getType());
		Assert.assertEquals(
				"JVBERi0xLjUNJeLjz9MNCjEgMCBvYmoNPDwvTWV0YWRhdGEgMiAwIFIvT0NQcm9wZXJ0aWVzPDwvRDw8L09OWzUgMCBSXS9PcmRl",
				response.getMediaContents().get(0).getData().substring(0, 100));
	}

	@Test  
	public void getDigitalAssets() throws ApiException {
		ApiClient apiClient = buildApiClient();

		GetDigitalAssetsApi requestApi = new GetDigitalAssetsApi(apiClient);

		GetDigitalAssetsEncryptedData encryptedData = new GetDigitalAssetsEncryptedData();
		encryptedData.setAccountNumber("5480981500100002");

		GetDigitalAssetsRequestSchemaEncryptedPayload encryptedPayload = new GetDigitalAssetsRequestSchemaEncryptedPayload();
		encryptedPayload.setEncryptedData(encryptedData);
		encryptedPayload.setOaepHashingAlgorithm("SHA512");
		encryptedPayload.setEncryptedKey("A1B2C3D4E5F6112233445566");
		encryptedPayload.setPublicKeyFingerprint("4c4ead5927f0df8117f178eea9308daa58e27c2b");

		GetDigitalAssetsRequestSchema requestSchema = new GetDigitalAssetsRequestSchema();
		requestSchema.setResponseHost("site2.payment-app-provider.com");
		requestSchema.setRequestId("123456");
		requestSchema.setEncryptedPayload(encryptedPayload);

		GetDigitalAssetsResponseSchema response = requestApi.getDigitalAssets(requestSchema);
		
		Assert.assertNotNull(response.getResponseId());
		Assert.assertEquals(null, response.getResponseHost());
		Assert.assertEquals(null, response.getBrandLogoAssetId());
		Assert.assertEquals(null, response.getIssuerLogoAssetId());
		Assert.assertEquals(null, response.getIsCoBranded());
		Assert.assertEquals(null, response.getCoBrandName());
		Assert.assertEquals(null, response.getCoBrandLogoAssetId());
		Assert.assertEquals(null, response.getCardBackgroundCombinedAssetId());
		Assert.assertEquals(null, response.getCardBackgroundAssetId());
		Assert.assertEquals(null, response.getIconAssetId());
		Assert.assertEquals(null, response.getForegroundColor());
		Assert.assertEquals(null, response.getIssuerName());
		Assert.assertEquals(null, response.getShortDescription());
		Assert.assertEquals(null, response.getLongDescription());
	}

	@Test
	public void getDeleteTest() throws ApiException {

		ApiClient apiClient = buildApiClient();

		DeleteApi deleteRequest = new DeleteApi(apiClient);
		DeleteRequestSchema deleteRequestSchema = new DeleteRequestSchema();
		deleteRequestSchema.setResponseHost("site2.payment-app-provider.com");
		deleteRequestSchema.setRequestId("123456");
		deleteRequestSchema.setPaymentAppInstanceId("123456789");
		List<String> tokenList = Arrays.asList(new String[] { "DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45" });
		deleteRequestSchema.setTokenUniqueReferences(tokenList);
		deleteRequestSchema.setCausedBy("CARDHOLDER");
		deleteRequestSchema.setReason("Lost/stolen device");
		deleteRequestSchema.setReasonCode("SUSPECTED_FRAUD");

		DeleteResponseSchema response = deleteRequest.deleteDigitization(deleteRequestSchema);
		Assert.assertEquals("site.1.sample.service.mastercard.com", response.getResponseHost());
		Assert.assertEquals("123456", response.getResponseId());
		Assert.assertEquals("DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45",
				response.getTokens().get(0).getTokenUniqueReference());
		Assert.assertEquals("DEACTIVATED", response.getTokens().get(0).getStatus());
		Assert.assertEquals(null, response.getTokens().get(0).getSuspendedBy());
		Assert.assertNotNull(response.getTokens().get(0).getStatusTimestamp());
	}

	@Test
	public void getTaskStatusTest() throws ApiException {

		ApiClient apiClient = buildApiClient();

		GetTaskStatusApi request = new GetTaskStatusApi(apiClient);
		GetTaskStatusRequestSchema getTaskStatusRequestSchema = new GetTaskStatusRequestSchema();
		getTaskStatusRequestSchema.setResponseHost("site2.payment-app-provider.com");
		getTaskStatusRequestSchema.setRequestId("123456");
		getTaskStatusRequestSchema.setTokenRequestorId("98765432101");
		getTaskStatusRequestSchema.setTaskId("123456");
		GetTaskStatusResponseSchema response = request.getTaskStatus(getTaskStatusRequestSchema);

		Assert.assertEquals("123456", response.getResponseId());
		Assert.assertEquals("site.1.sample.service.mastercard.com", response.getResponseHost());
		Assert.assertEquals("PENDING", response.getStatus());
	}

	@Test 
	public void searchTokensTest() throws ApiException {

		SearchTokensRequestSchema searchTokensRequestSchema = new SearchTokensRequestSchema();
		searchTokensRequestSchema.setRequestId("123456");
		searchTokensRequestSchema.setResponseHost("site2.payment-app-provider.com");
		searchTokensRequestSchema.setTokenRequestorId("98765432101");		
		searchTokensRequestSchema.setFundingAccountInfo(buildFundingAccountInfo());

		SearchTokensResponseSchema response = new SearchTokensApi(buildApiClient()).searchTokens(searchTokensRequestSchema);
		
		Assert.assertEquals("site.1.sample.service.mastercard.com", response.getResponseHost());
		Assert.assertEquals("123456", response.getResponseId());
		
		Assert.assertEquals("DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45", response.getTokens().get(0).getTokenUniqueReference());
		Assert.assertEquals("ACTIVE", response.getTokens().get(0).getStatus());
		Assert.assertEquals(null, response.getTokens().get(0).getSuspendedBy());
		Assert.assertEquals("2017-09-05T00:00:00.000Z", response.getTokens().get(0).getStatusTimestamp());
		Assert.assertEquals(null, response.getTokens().get(0).getProductConfig());
		Assert.assertEquals(null, response.getTokens().get(0).getTokenInfo());

		Assert.assertEquals("DWSPMC00000000032d72d4ffcb2f4136a0532d32d72d4fcb", response.getTokens().get(1).getTokenUniqueReference());
		Assert.assertEquals("ACTIVE", response.getTokens().get(1).getStatus());
		Assert.assertEquals(null, response.getTokens().get(1).getSuspendedBy());
		Assert.assertEquals("2017-09-06T00:00:00.000Z", response.getTokens().get(1).getStatusTimestamp());
		Assert.assertEquals(null, response.getTokens().get(1).getProductConfig());
		Assert.assertEquals(null, response.getTokens().get(1).getTokenInfo());
		
		Assert.assertEquals("DWSPMC000000000fcb2f4136b2f4136a0532d2f4136a0532", response.getTokens().get(2).getTokenUniqueReference());
		Assert.assertEquals("SUSPENDED", response.getTokens().get(2).getStatus());
		Assert.assertEquals("TOKEN_REQUESTOR", response.getTokens().get(2).getSuspendedBy().get(0));
		Assert.assertEquals("2017-09-07T00:00:00.000Z", response.getTokens().get(2).getStatusTimestamp());
		Assert.assertEquals(null, response.getTokens().get(2).getProductConfig());
		Assert.assertEquals(null, response.getTokens().get(2).getTokenInfo());
	}

	@Test
	public void getTokenTest() throws ApiException {
		GetTokenRequestSchema schema = new GetTokenRequestSchema();
		schema.setResponseHost("site2.payment-app-provider.com");
		schema.setRequestId("123456");
		schema.setPaymentAppInstanceId("123456789");
		schema.setTokenUniqueReference("DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45");
		schema.setIncludeTokenDetail("true");

		ApiClient apiClient = buildApiClient();
		GetTokenResponseSchema response = new GetTokenApi(apiClient).getToken(schema);

		Assert.assertEquals("123456", response.getResponseId());
		Assert.assertEquals("ACTIVE", response.getToken().getStatus());
		Assert.assertEquals("5123456789012345", response.getTokenDetail().getEncryptedData().getTokenNumber());
		Assert.assertEquals("12", response.getTokenDetail().getEncryptedData().getExpiryMonth());
		Assert.assertEquals("22", response.getTokenDetail().getEncryptedData().getExpiryYear());
		Assert.assertEquals("500181d9f8e0629211e3949a08002",
				response.getTokenDetail().getEncryptedData().getPaymentAccountReference());
	}

	@Test
	public void transactTest() throws ApiException {

		ApiClient apiClient = buildApiClient();

		TransactApi transact = new TransactApi(apiClient);

		TransactRequestSchema transactRequestSchema = new TransactRequestSchema();
		transactRequestSchema.setResponseHost("site2.payment-app-provider.com");
		transactRequestSchema.setRequestId("123456");
		transactRequestSchema.setTokenUniqueReference("DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45");
		transactRequestSchema.setDsrpType("UCAF");
		transactRequestSchema.setUnpredictableNumber("23424563");

		TransactResponseSchema response = transact.createTransact(transactRequestSchema);

		Assert.assertNotNull(response.getResponseId());  
		Assert.assertEquals(null, response.getResponseHost());
		Assert.assertEquals(null, response.getEncryptedPayload().getPublicKeyFingerprint());
		Assert.assertEquals(null, response.getEncryptedPayload().getEncryptedKey());
		Assert.assertEquals(null, response.getEncryptedPayload().getOaepHashingAlgorithm());
		Assert.assertEquals(null, response.getEncryptedPayload().getIv());
		Assert.assertEquals("5204240500000505", response.getEncryptedPayload().getEncryptedData().getAccountNumber());
		Assert.assertNotNull(response.getEncryptedPayload().getEncryptedData().getApplicationExpiryDate());
		Assert.assertEquals("00", response.getEncryptedPayload().getEncryptedData().getPanSequenceNumber());
		Assert.assertEquals("5204240500000505D19022010000000000000F",
				response.getEncryptedPayload().getEncryptedData().getTrack2Equivalent());
		Assert.assertEquals("AF1ajnoLKKj8AAKhssPUGgADFA==",
				response.getEncryptedPayload().getEncryptedData().getDe48se43Data());
	}

	/**
	 * ErrorResponse.errors schema has been changed at .yaml file. Should have the following schema:
	 * 		errors:
     *  		type: array
     *   		items:
     *      		$ref: '#/definitions/Error'      
     *    		description: | 
     *     			__CONDITIONAL__ <br>Returned if one or more errors occurred performing the operation. Not present Get Token error conditions.     
	 */
	@Test
	public void parseError() {
		
		String errorMsg = "{\"errorCode\":\"INVALID_PAN\",\"errorDescription\":\"Invalid PAN\",\"errors\":[{\"source\":\"INPUT\",\"reasonCode\":\"INVALID_PAN\",\"description\":\"Invalid PAN\"}],\"responseId\":\"1c8a20b7-8980-4307-b6ab-7b6f3ccb6dd2\",\"responseHost\":\"stl.services.mastercard.com/mtf/mdes\"}";
		
		Type type = new TypeToken<ErrorsResponse>() {
		}.getType();
		
		ErrorsResponse errorsResponse = new JSON().deserialize(errorMsg, type);
		
		Assert.assertEquals("INVALID_PAN", errorsResponse.getErrorCode());
		Assert.assertEquals("Invalid PAN", errorsResponse.getErrorDescription());
		Assert.assertEquals("1c8a20b7-8980-4307-b6ab-7b6f3ccb6dd2", errorsResponse.getResponseId());
		Assert.assertEquals("stl.services.mastercard.com/mtf/mdes", errorsResponse.getResponseHost());
		Assert.assertEquals("INPUT", errorsResponse.getErrors().get(0).getSource());
		Assert.assertEquals("INVALID_PAN", errorsResponse.getErrors().get(0).getReasonCode());
		Assert.assertEquals("Invalid PAN", errorsResponse.getErrors().get(0).getDescription());
	}	

}