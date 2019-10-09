package com.wallee.sdk.mdes;

import java.nio.file.Paths;
import java.nio.file.Files;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Properties;
import java.util.Optional;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import com.mastercard.developer.utils.AuthenticationUtils;
import com.mastercard.developer.utils.EncryptionUtils;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.Response;
import com.wallee.sdk.mdes.ApiClient;
import com.wallee.sdk.mdes.ApiClient.ApiClientConfiguration;
import com.wallee.sdk.mdes.ApiException;
import com.wallee.sdk.mdes.api.GetTokenApi;
import com.wallee.sdk.mdes.api.TokenizeApi;
import com.wallee.sdk.mdes.model.AccountHolderData;
import com.wallee.sdk.mdes.model.BillingAddress;
import com.wallee.sdk.mdes.model.CardAccountDataInbound;
import com.wallee.sdk.mdes.model.FundingAccountData;
import com.wallee.sdk.mdes.model.FundingAccountInfo;
import com.wallee.sdk.mdes.model.FundingAccountInfoEncryptedPayload;
import com.wallee.sdk.mdes.model.GetTokenRequestSchema;
import com.wallee.sdk.mdes.model.GetTokenResponseSchema;
import com.wallee.sdk.mdes.model.TokenizeRequestSchema;
import com.wallee.sdk.mdes.model.TokenizeResponseSchema;

public class ApiClientTest {

	private ApiClient apiClient;
	
	private final String signingKeyAlias;
	private final String signingKeyPassword; 
	private final String consumerKey;

	public ApiClientTest() throws IOException, GeneralSecurityException {
		signingKeyAlias = Optional.ofNullable(System.getenv("MDES_SIGNING_KEY_ALIAS")).orElseThrow(() -> new NullPointerException("MDES_SIGNING_KEY_ALIAS"));
		signingKeyPassword = Optional.ofNullable(System.getenv("MDES_SIGNING_KEY_PASSWORD")).orElseThrow(() -> new NullPointerException("MDES_SIGNING_KEY_PASSWORD"));
		consumerKey = Optional.ofNullable(System.getenv("MDES_CONSUMER_KEY")).orElseThrow(() -> new NullPointerException("MDES_CONSUMER_KEY"));
	 
		String path = "./src/test/resources/";
		
		System.setProperty("javax.net.ssl.trustStoreType", "jks");
		System.setProperty("javax.net.ssl.keyStoreType", "pkcs12"); 		
		
		System.out.println(signingKeyAlias.charAt(0) + "--" + signingKeyAlias.charAt(signingKeyAlias.length() - 1));
		System.out.println(signingKeyPassword.charAt(0) + "--" + signingKeyPassword.charAt(signingKeyPassword.length() - 1));
		System.out.println(consumerKey.charAt(0) + "--" + consumerKey.charAt(consumerKey.length() - 1));
		
		

		Path file = Paths.get(path + "wallee_M4M-sandbox.p12");
		System.out.println(Files.size(file));		

		PrivateKey signingKey = AuthenticationUtils.loadSigningKey(//
				path + "wallee_M4M-sandbox.p12", //
				signingKeyAlias, //
				signingKeyPassword);

		PrivateKey decryptionPrivateKey = EncryptionUtils
				.loadDecryptionKey(path + "private-key-decrypt.pem");
		Certificate publicKeyEncryptionCertificate = EncryptionUtils
				.loadEncryptionCertificate(path + "public-key-encrypt.crt");

		ApiClientConfiguration apiClientConfiguration = ApiClientConfiguration.building()//
				.setEndpoint(ApiClient.EndPoint.SANDBOX)//
				.setSigningKey(signingKey)//
				.setDecryptionPrivateKey(decryptionPrivateKey)//
				.setPublicKeyEncryptionCertificate(publicKeyEncryptionCertificate)//
				.setConsumerKey(consumerKey)
				.build(); 
		
		apiClient = new ApiClient(apiClientConfiguration);
	}

	@Ignore // TODO
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
//		tokenizeRequestSchema.setTokenizationAuthenticationValue("RHVtbXkgYmFzZSA2NCBkYXRhIC0gdGhpcyBpcyBub3QgYSByZWFsIFRBViBleGFtcGxl");

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

	@Test
	public void getTokenTest() throws ApiException {
		GetTokenRequestSchema schema = new GetTokenRequestSchema();
		schema.setResponseHost("site2.payment-app-provider.com");
		schema.setRequestId("123456");
		schema.setPaymentAppInstanceId("123456789");
		schema.setTokenUniqueReference("DWSPMC000000000132d72d4fcb2f4136a0532d3093ff1a45");
		schema.setIncludeTokenDetail("true");

		GetTokenResponseSchema response = new GetTokenApi(apiClient).getToken(schema);

		Assert.assertEquals("123456", response.getResponseId());
		Assert.assertEquals("ACTIVE", response.getToken().getStatus());
		Assert.assertEquals("5123456789012345", response.getTokenDetail().getEncryptedData().getTokenNumber());
		Assert.assertEquals("12", response.getTokenDetail().getEncryptedData().getExpiryMonth());
		Assert.assertEquals("22", response.getTokenDetail().getEncryptedData().getExpiryYear());
		Assert.assertEquals("500181d9f8e0629211e3949a08002",
				response.getTokenDetail().getEncryptedData().getPaymentAccountReference());
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

		Response response = apiClient.getHttpClient().newCall(request).execute();
		System.out.println(response);
	}

}