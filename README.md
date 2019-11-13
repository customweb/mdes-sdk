# wallee-mdes-sdk

## Requirements

Building the API client library requires [Maven](https://maven.apache.org/) to be installed.

## Installation

To install the API client library to your local Maven repository, simply execute:

```shell
mvn install
```

To deploy it to a remote Maven repository instead, configure the settings of the repository and execute:

```shell
mvn deploy
```

Refer to the [official documentation](https://maven.apache.org/plugins/maven-deploy-plugin/usage.html) for more information.

### Maven users

Add this dependency to your project's POM:

```xml
<dependency>
    <groupId>com.wallee</groupId>
    <artifactId>wallee-mdes-sdk</artifactId>
    <version>1.1.5</version>
    <scope>compile</scope>
</dependency>
```

### Gradle users

Add this dependency to your project's build file:

```groovy
compile "com.wallee:wallee-mdes-sdk:1.1.5"
```

### Others

At first generate the JAR by executing:

    mvn package

Then manually install the following JARs:

* target/wallee-mdes-sdk-1.1.5.jar
* target/lib/*.jar

## Getting Started

Please follow the [installation](#installation) instruction and execute the following Java code:

```java

import com.wallee.sdk.mdes.*;
import com.wallee.sdk.mdes.auth.*;
import com.wallee.sdk.mdes.model.*;
import com.wallee.sdk.mdes.api.DeleteApi;

import java.io.File;
import java.util.*;

public class DeleteApiExample {

    public static void main(String[] args) {
        
        DeleteApi apiInstance = new DeleteApi();
        DeleteRequestSchema deleteRequestSchema = new DeleteRequestSchema(); // DeleteRequestSchema | Contains the details of the request message. 
        try {
            DeleteResponseSchema result = apiInstance.deleteDigitization(deleteRequestSchema);
            System.out.println(result);
        } catch (ApiException e) {
            System.err.println("Exception when calling DeleteApi#deleteDigitization");
            e.printStackTrace();
        }
    }
}

```

## Documentation for API Endpoints

All URIs are relative to *https://api.mastercard.com/mdes*

Class | Method | HTTP request | Description
------------ | ------------- | ------------- | -------------
*DeleteApi* | [**deleteDigitization**](docs/DeleteApi.md#deleteDigitization) | **POST** /digitization/#env/1/0/delete | Used to delete one or more Tokens. The API is limited to 10 Tokens per request.
*GetAssetApi* | [**getAsset**](docs/GetAssetApi.md#getAsset) | **GET** /assets/#env/1/0/asset/{AssetId} | Used to retrieve static Assets from the MDES repository.
*GetDigitalAssetsApi* | [**getDigitalAssets**](docs/GetDigitalAssetsApi.md#getDigitalAssets) | **POST** /digitization/#env/1/0/getDigitalAssets | Used to retrieve digital assets derived from a funding PAN.
*GetTaskStatusApi* | [**getTaskStatus**](docs/GetTaskStatusApi.md#getTaskStatus) | **POST** /digitization/#env/1/0/getTaskStatus | Used to check the status of any asynchronous task that was previously requested.
*GetTokenApi* | [**getToken**](docs/GetTokenApi.md#getToken) | **POST** /digitization/#env/1/0/getToken | Used to get the status and details of a single given Token.
*NotifyTokenUpdatedApi* | [**notifyTokenUpdateForTokenStateChange**](docs/NotifyTokenUpdatedApi.md#notifyTokenUpdateForTokenStateChange) | **POST** /digitization/#env/1/0/notifyTokenUpdated | Outbound API used by MDES to notify the Token Requestor of significant Token updates, such as when the Token is activated, suspended, unsuspended or deleted; or when information about the Token or its product configuration has changed.
*SearchTokensApi* | [**searchTokens**](docs/SearchTokensApi.md#searchTokens) | **POST** /digitization/#env/1/0/searchTokens | Used to get basic token information for all tokens on a specified device, or all tokens mapped to the given Account PAN.
*SuspendApi* | [**createSuspend**](docs/SuspendApi.md#createSuspend) | **POST** /digitization/#env/1/0/suspend | Used to temporarily suspend one or more Tokens.
*TokenizeApi* | [**createTokenize**](docs/TokenizeApi.md#createTokenize) | **POST** /digitization/#env/1/0/tokenize | Used to digitize a card to create a server-based Token.
*TransactApi* | [**createTransact**](docs/TransactApi.md#createTransact) | **POST** /remotetransaction/#env/1/0/transact | Used by the Token Requestor to create a Digital Secure Remote Payment (\&quot;DSRP\&quot;) transaction cryptogram using the credentials stored within MDES in order to perform a DSRP transaction.
*UnsuspendApi* | [**createUnsuspend**](docs/UnsuspendApi.md#createUnsuspend) | **POST** /digitization/#env/1/0/unsuspend | Used to unsuspend one or more previously suspended Tokens. The API is limited to 10 Tokens per request.


## Documentation for Models

 - [AccountHolderData](docs/AccountHolderData.md)
 - [AccountHolderDataOutbound](docs/AccountHolderDataOutbound.md)
 - [AssetResponseSchema](docs/AssetResponseSchema.md)
 - [AuthenticationMethods](docs/AuthenticationMethods.md)
 - [BillingAddress](docs/BillingAddress.md)
 - [CardAccountDataInbound](docs/CardAccountDataInbound.md)
 - [CardAccountDataOutbound](docs/CardAccountDataOutbound.md)
 - [DecisioningData](docs/DecisioningData.md)
 - [DeleteRequestSchema](docs/DeleteRequestSchema.md)
 - [DeleteResponseSchema](docs/DeleteResponseSchema.md)
 - [EncryptedPayload](docs/EncryptedPayload.md)
 - [EncryptedPayloadTransact](docs/EncryptedPayloadTransact.md)
 - [Error](docs/Error.md)
 - [ErrorsResponse](docs/ErrorsResponse.md)
 - [FundingAccountData](docs/FundingAccountData.md)
 - [FundingAccountInfo](docs/FundingAccountInfo.md)
 - [FundingAccountInfoEncryptedPayload](docs/FundingAccountInfoEncryptedPayload.md)
 - [GatewayError](docs/GatewayError.md)
 - [GatewayErrorsResponse](docs/GatewayErrorsResponse.md)
 - [GatewayErrorsSchema](docs/GatewayErrorsSchema.md)
 - [GetDigitalAssetsEncryptedData](docs/GetDigitalAssetsEncryptedData.md)
 - [GetDigitalAssetsRequestSchema](docs/GetDigitalAssetsRequestSchema.md)
 - [GetDigitalAssetsRequestSchemaEncryptedPayload](docs/GetDigitalAssetsRequestSchemaEncryptedPayload.md)
 - [GetDigitalAssetsResponseSchema](docs/GetDigitalAssetsResponseSchema.md)
 - [GetTaskStatusRequestSchema](docs/GetTaskStatusRequestSchema.md)
 - [GetTaskStatusResponseSchema](docs/GetTaskStatusResponseSchema.md)
 - [GetTokenRequestSchema](docs/GetTokenRequestSchema.md)
 - [GetTokenResponseSchema](docs/GetTokenResponseSchema.md)
 - [MediaContent](docs/MediaContent.md)
 - [NotifyTokenEncryptedPayload](docs/NotifyTokenEncryptedPayload.md)
 - [NotifyTokenUpdatedRequestSchema](docs/NotifyTokenUpdatedRequestSchema.md)
 - [NotifyTokenUpdatedResponseSchema](docs/NotifyTokenUpdatedResponseSchema.md)
 - [PhoneNumber](docs/PhoneNumber.md)
 - [ProductConfig](docs/ProductConfig.md)
 - [SearchTokensRequestSchema](docs/SearchTokensRequestSchema.md)
 - [SearchTokensResponseSchema](docs/SearchTokensResponseSchema.md)
 - [SuspendRequestSchema](docs/SuspendRequestSchema.md)
 - [SuspendResponseSchema](docs/SuspendResponseSchema.md)
 - [Token](docs/Token.md)
 - [TokenDetail](docs/TokenDetail.md)
 - [TokenDetailData](docs/TokenDetailData.md)
 - [TokenDetailDataGetTokenOnly](docs/TokenDetailDataGetTokenOnly.md)
 - [TokenDetailDataPAROnly](docs/TokenDetailDataPAROnly.md)
 - [TokenDetailDataTCCOnly](docs/TokenDetailDataTCCOnly.md)
 - [TokenDetailGetTokenOnly](docs/TokenDetailGetTokenOnly.md)
 - [TokenDetailPAROnly](docs/TokenDetailPAROnly.md)
 - [TokenForLCM](docs/TokenForLCM.md)
 - [TokenInfo](docs/TokenInfo.md)
 - [TokenizeRequestSchema](docs/TokenizeRequestSchema.md)
 - [TokenizeResponseSchema](docs/TokenizeResponseSchema.md)
 - [TransactEncryptedData](docs/TransactEncryptedData.md)
 - [TransactError](docs/TransactError.md)
 - [TransactRequestSchema](docs/TransactRequestSchema.md)
 - [TransactResponseSchema](docs/TransactResponseSchema.md)
 - [UnSuspendRequestSchema](docs/UnSuspendRequestSchema.md)
 - [UnSuspendResponseSchema](docs/UnSuspendResponseSchema.md)


## Documentation for Authorization

All endpoints do not require authorization.
Authentication schemes defined for the API:

## Recommendation

It's recommended to create an instance of `ApiClient` per thread in a multithreaded environment to avoid any potential issues.

## Author



