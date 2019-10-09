package com.wallee.sdk.mdes;

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.List;
import java.util.Optional;

import java.util.Base64;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.mastercard.developer.utils.EncryptionUtils;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.Response;
import com.wallee.sdk.mdes.ApiClient.ApiClientConfiguration;
import com.wallee.sdk.mdes.api.DeleteApi;
import com.wallee.sdk.mdes.api.GetAssetApi;
import com.wallee.sdk.mdes.api.GetDigitalAssetsApi;
import com.wallee.sdk.mdes.api.GetTaskStatusApi;
import com.wallee.sdk.mdes.api.GetTokenApi;
import com.wallee.sdk.mdes.api.SearchTokensApi;
import com.wallee.sdk.mdes.api.TokenizeApi;
import com.wallee.sdk.mdes.api.TransactApi;
import com.wallee.sdk.mdes.model.AccountHolderData;
import com.wallee.sdk.mdes.model.AssetResponseSchema;
import com.wallee.sdk.mdes.model.BillingAddress;
import com.wallee.sdk.mdes.model.CardAccountDataInbound;
import com.wallee.sdk.mdes.model.DeleteRequestSchema;
import com.wallee.sdk.mdes.model.DeleteResponseSchema;
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
	public static void loadFiles() throws IOException, GeneralSecurityException {

		System.out.println("@BeforeClass");

		signingKeyAlias = Optional.ofNullable(System.getenv("MDES_SIGNING_KEY_ALIAS"))
				.orElseThrow(() -> new NullPointerException("MDES_SIGNING_KEY_ALIAS"));
		signingKeyPassword = Optional.ofNullable(System.getenv("MDES_SIGNING_KEY_PASSWORD"))
				.orElseThrow(() -> new NullPointerException("MDES_SIGNING_KEY_PASSWORD"));
		consumerKey = Optional.ofNullable(System.getenv("MDES_CONSUMER_KEY"))
				.orElseThrow(() -> new NullPointerException("MDES_CONSUMER_KEY"));

		encodedBase64PublicKey = Optional.ofNullable(System.getenv("MDES_ENCODED_BASE64_PUBLIC_KEY"))
				.orElseThrow(() -> new NullPointerException("MDES_ENCODED_BASE64_PUBLIC_KEY"));

		encodedBase64SigningKey = Optional.ofNullable(System.getenv("MDES_ENCODED_BASE64_SIGNING_KEY"))
				.orElseThrow(() -> new NullPointerException("MDES_ENCODED_BASE64_SIGNING_KEY"));

		decryptionPrivateKey = EncryptionUtils.loadDecryptionKey("./src/test/resources/" + "private-key-decrypt.pem");

		String publicKeyStr = new String(Base64.getDecoder().decode(encodedBase64PublicKey.getBytes(StandardCharsets.UTF_8)),
				StandardCharsets.UTF_8);
		try (InputStream in = new ByteArrayInputStream(publicKeyStr.getBytes(StandardCharsets.UTF_8))) {
			publicKeyEncryptionCertificate = loadEncryptionCertificate(in);
		}
		
		byte[] decodeP12 = Base64.getDecoder().decode(encodedBase64SigningKey.getBytes(StandardCharsets.UTF_8));

		signingKey = loadSigningKey(//
				decodeP12, signingKeyAlias, //
				signingKeyPassword);
	}

	public static Certificate loadEncryptionCertificate(InputStream inStream)
			throws CertificateException, NoSuchProviderException {
		CertificateFactory factory = CertificateFactory.getInstance("X.509", "SUN");
		return factory.generateCertificate(inStream);
	}

	public static PrivateKey loadSigningKey(byte[] pkcs12Key, String signingKeyAlias, String signingKeyPassword)
			throws IOException, NoSuchProviderException, KeyStoreException, CertificateException,
			NoSuchAlgorithmException, UnrecoverableKeyException {
		KeyStore pkcs12KeyStore = KeyStore.getInstance("PKCS12", "SunJSSE");

		try (InputStream in = new ByteArrayInputStream(pkcs12Key)) {
			pkcs12KeyStore.load(in, signingKeyPassword.toCharArray());
			return (PrivateKey) pkcs12KeyStore.getKey(signingKeyAlias, signingKeyPassword.toCharArray());
		}

	}

	private ApiClient buildApiClient() {

		ApiClientConfiguration apiClientConfiguration = ApiClientConfiguration.building()//
				.setEndpoint(ApiClient.EndPoint.SANDBOX)//
				.setSigningKey(signingKey)//
				.setDecryptionPrivateKey(decryptionPrivateKey)//
				.setPublicKeyEncryptionCertificate(publicKeyEncryptionCertificate)//
				.setConsumerKey(consumerKey).build();

		return new ApiClient(apiClientConfiguration);
	}

	@Ignore // TODO
	@Test // TODO it is failing
	public void tokenizeTest() throws ApiException {

		TokenizeRequestSchema tokenizeRequestSchema = new TokenizeRequestSchema();
		tokenizeRequestSchema.setResponseHost("site1.payment-app-provider.com");
		tokenizeRequestSchema.setRequestId("123456");
		tokenizeRequestSchema.setTokenType("CLOUD");
		tokenizeRequestSchema.setTokenRequestorId("98765432101");
		tokenizeRequestSchema.setTaskId("123456");
		tokenizeRequestSchema.setFundingAccountInfo(buildFundingAccountInfo());
		tokenizeRequestSchema.setConsumerLanguage("en");
//		tokenizeRequestSchema.setTokenizationAuthenticationValue("RHVtbXkgYmFzZSA2NCBkYXRhIC0gdGhpcyBpcyBub3QgYSByZWFsIFRBViBleGFtcGxl");

		ApiClient apiClient = buildApiClient();

		TokenizeResponseSchema response = new TokenizeApi(apiClient).createTokenize(tokenizeRequestSchema);

		System.out.println(response);
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

	// TODO remove
	// test if tokenization works if we force to use the provide public key
	// fingerprint and not the calculated one, as they suggest in doc
	public void testingCode() throws IOException {

//		String encryptedPayload = "{\"responseHost\":\"site1.payment-app-provider.com\",\"requestId\":\"123456\",\"tokenType\":\"CLOUD\",\"tokenRequestorId\":\"98765432101\",\"taskId\":\"123456\",\"fundingAccountInfo\":{\"encryptedPayload\":{\"encryptedData\":\"1b560f1428a7f1e792e49c3b4335e71167b8d3734a2e1117605d5a9aa963437568d1af7c90d009aab541b473320b09399aff8f38b3f93b0144c3f85d672cd3d841dbceb8f806218d794f2f2d5ffd502fd1f06cf1617d854369ad08070dd506a84a974eb20fc7f1ad9bb67222ebe8b820e56d2eeb5da2bd3d7e6267da78bd7d7dac1ee42663444cf0812e43226bbf2dc79c6506c9e8c0ef628ac8dffc5e8cc9d713e6028c6fb14254a73fb28731f0d195faf17c95ede081ac34b0c3f0de21e767585f0be9bde4db1d779b159e2cbed88c175846ac7f9cfa557fed4376d8fbff30c76afa5552a8bee778280c63a49b1732a96b9106a7acfe0f7b5423e63efa4ad6a2fca1928b7dbaa166d7c50e95ffc61ff81cf594c5397214340268400ac9e7da1b676c0cb957f859a0bd33c6f9fd42a47dd7683bf747aabd90035ac3a50d22eac9dfbd7dc49e48a40d9a9962b00c8397c78030232c7f0ec436c81467fdc5dd1d\",\"iv\":\"01f0347ccfaef1ffd26b276bd8c74c13\",\"encryptedKey\":\"0b88f2cff5cabb634b1debf9603e870d5a8007c26b50eebddc77f1c89ca69da948ef944587fd365e34aa57b258f7ccd91ff0c2bf75a6f706701a24b8cfc40c53bd9cd93c5843a3feff6bb75020d351c21afaedf02ab28edf0a1076d57a7fa7ff4641ad2e511a03d403eb4f2a230ef5edacf0da499e796c06f52226d63ed6e5d3f2ca0d19440ba555bf0b74ca9b7695fc287815ef2fcc8abbb1744e08bb5c8ece320eac65baddda829f3297a838b5c64561d3ec88116b3a8f044e4793267d9197038a441cd6db2ffdae8b18d1b611a1aec3ed2ba050ad5011f35f1f1d98cc3add37e9ab3394f8c328f6cc2aa8500e44b7a42db06326e3baf5a8c1ffa2c1bbb787\",\"publicKeyFingerprint\":\"3e3ff1c50fd4046b9a80c39d3d077f7313b92ea01462744bfe50b62769dbef68\",\"oaepHashingAlgorithm\":\"SHA512\"}},\"consumerLanguage\":\"en\"}";

		String encryptedPayload = "{\"responseHost\":\"site1.payment-app-provider.com\",\"requestId\":\"123456\",\"tokenType\":\"CLOUD\",\"tokenRequestorId\":\"98765432101\",\"taskId\":\"123456\",\"fundingAccountInfo\":{\"encryptedPayload\":{\"encryptedData\":\"1b560f1428a7f1e792e49c3b4335e71167b8d3734a2e1117605d5a9aa963437568d1af7c90d009aab541b473320b09399aff8f38b3f93b0144c3f85d672cd3d841dbceb8f806218d794f2f2d5ffd502fd1f06cf1617d854369ad08070dd506a84a974eb20fc7f1ad9bb67222ebe8b820e56d2eeb5da2bd3d7e6267da78bd7d7dac1ee42663444cf0812e43226bbf2dc79c6506c9e8c0ef628ac8dffc5e8cc9d713e6028c6fb14254a73fb28731f0d195faf17c95ede081ac34b0c3f0de21e767585f0be9bde4db1d779b159e2cbed88c175846ac7f9cfa557fed4376d8fbff30c76afa5552a8bee778280c63a49b1732a96b9106a7acfe0f7b5423e63efa4ad6a2fca1928b7dbaa166d7c50e95ffc61ff81cf594c5397214340268400ac9e7da1b676c0cb957f859a0bd33c6f9fd42a47dd7683bf747aabd90035ac3a50d22eac9dfbd7dc49e48a40d9a9962b00c8397c78030232c7f0ec436c81467fdc5dd1d\",\"iv\":\"01f0347ccfaef1ffd26b276bd8c74c13\",\"encryptedKey\":\"0b88f2cff5cabb634b1debf9603e870d5a8007c26b50eebddc77f1c89ca69da948ef944587fd365e34aa57b258f7ccd91ff0c2bf75a6f706701a24b8cfc40c53bd9cd93c5843a3feff6bb75020d351c21afaedf02ab28edf0a1076d57a7fa7ff4641ad2e511a03d403eb4f2a230ef5edacf0da499e796c06f52226d63ed6e5d3f2ca0d19440ba555bf0b74ca9b7695fc287815ef2fcc8abbb1744e08bb5c8ece320eac65baddda829f3297a838b5c64561d3ec88116b3a8f044e4793267d9197038a441cd6db2ffdae8b18d1b611a1aec3ed2ba050ad5011f35f1f1d98cc3add37e9ab3394f8c328f6cc2aa8500e44b7a42db06326e3baf5a8c1ffa2c1bbb787\",\"publicKeyFingerprint\":\"8FC11150A7508F14BACA07285703392A399CC57C\",\"oaepHashingAlgorithm\":\"SHA512\"}},\"consumerLanguage\":\"en\"}";

		Request request = new Request.Builder()
				.url("https://sandbox.api.mastercard.com/mdes/digitization/static/1/0/tokenize").build();

		Request.Builder requestBuilder = request.newBuilder();

		MediaType mediaType = MediaType.parse("application/json; charset=utf-8");
		RequestBody encryptedBody = RequestBody.create(mediaType, encryptedPayload);
		request = requestBuilder.method("POST", encryptedBody).header("Content-Length", "1624").build();

		ApiClient apiClient = buildApiClient();

		Response response = apiClient.getHttpClient().newCall(request).execute();
		System.out.println(response);
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

	@Ignore
	@Test // TODO it is failing
	public void getDigitalAssets() throws ApiException {
		ApiClient apiClient = buildApiClient();

		GetDigitalAssetsApi requestApi = new GetDigitalAssetsApi(apiClient);

		GetDigitalAssetsEncryptedData encryptedData = new GetDigitalAssetsEncryptedData();
		encryptedData.setAccountNumber("5480981500100002");

		GetDigitalAssetsRequestSchemaEncryptedPayload encryptedPayload = new GetDigitalAssetsRequestSchemaEncryptedPayload();
		encryptedPayload.setEncryptedData(encryptedData);
//		encryptedPayload.setOaepHashingAlgorithm("SHA512");
//		encryptedPayload.setEncryptedKey("A1B2C3D4E5F6112233445566");
//		encryptedPayload.setPublicKeyFingerprint("4c4ead5927f0df8117f178eea9308daa58e27c2b");

		GetDigitalAssetsRequestSchema requestSchema = new GetDigitalAssetsRequestSchema();
		requestSchema.setResponseHost("site2.payment-app-provider.com");
		requestSchema.setRequestId("123456");
		requestSchema.setEncryptedPayload(encryptedPayload);

		GetDigitalAssetsResponseSchema response = requestApi.getDigitalAssets(requestSchema);

		fail();
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
		Assert.assertEquals("2019-10-09",
				response.getTokens().get(0).getStatusTimestamp().substring(0, "2019-10-09".length()));
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

	@Ignore
	@Test // TODO coding not ended.
	public void searchTokensTest() throws ApiException {

		ApiClient apiClient = buildApiClient();

		SearchTokensApi requestApi = new SearchTokensApi(apiClient);

		SearchTokensRequestSchema searchTokensRequestSchema = new SearchTokensRequestSchema();
		searchTokensRequestSchema.setRequestId("123456");
		searchTokensRequestSchema.setResponseHost("site2.payment-app-provider.com");

		FundingAccountInfo fundingAccountInfo = new FundingAccountInfo();

		searchTokensRequestSchema.setFundingAccountInfo(fundingAccountInfo);

		SearchTokensResponseSchema response = requestApi.searchTokens(searchTokensRequestSchema);

		fail();
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

		// Assert.assertEquals("4fd19399-8c77-48ac-9105-7380ff72a198",
		// response.getResponseId()); always it returns different
		Assert.assertEquals(null, response.getResponseHost());
		Assert.assertEquals(null, response.getEncryptedPayload().getPublicKeyFingerprint());
		Assert.assertEquals(null, response.getEncryptedPayload().getEncryptedKey());
		Assert.assertEquals(null, response.getEncryptedPayload().getOaepHashingAlgorithm());
		Assert.assertEquals(null, response.getEncryptedPayload().getIv());
		Assert.assertEquals("5204240500000505", response.getEncryptedPayload().getEncryptedData().getAccountNumber());
		Assert.assertEquals("20191109", response.getEncryptedPayload().getEncryptedData().getApplicationExpiryDate());
		Assert.assertEquals("00", response.getEncryptedPayload().getEncryptedData().getPanSequenceNumber());
		Assert.assertEquals("5204240500000505D19022010000000000000F",
				response.getEncryptedPayload().getEncryptedData().getTrack2Equivalent());
		Assert.assertEquals("AF1ajnoLKKj8AAKhssPUGgADFA==",
				response.getEncryptedPayload().getEncryptedData().getDe48se43Data());
	}

	public static void main(String[] args) throws ApiException {
		new ApiClientTest().getAssetTest();
	}

}