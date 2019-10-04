/*
 * MDES for Merchants
 * The MDES APIs are designed as RPC style stateless web services where each API endpoint represents an operation to be performed.  All request and response payloads are sent in the JSON (JavaScript Object Notation) data-interchange format. Each endpoint in the API specifies the HTTP Method used to access it. All strings in request and response objects are to be UTF-8 encoded.  Each API URI includes the major and minor version of API that it conforms to.  This will allow multiple concurrent versions of the API to be deployed simultaneously. <br> __Authentication__ Mastercard uses OAuth 1.0a with body hash extension for authenticating the API clients. This requires every request that you send to  Mastercard to be signed with an RSA private key. A private-public RSA key pair must be generated consisting of: <br> 1 . A private key for the OAuth signature for API requests. It is recommended to keep the private key in a password-protected or hardware keystore. <br> 2. A public key is shared with Mastercard during the project setup process through either a certificate signing request (CSR) or the API Key Generator. Mastercard will use the public key to verify the OAuth signature that is provided on every API call.<br>  An OAUTH1.0a signer library is available on [GitHub](https://github.com/Mastercard/oauth1-signer-java) <br>  __Encryption__<br>  All communications between Issuer web service and the Mastercard gateway is encrypted using TLS. <br> __Additional Encryption of Sensitive Data__ In addition to the OAuth authentication, when using MDES Digital Enablement Service, any PCI sensitive and all account holder Personally Identifiable Information (PII) data must be encrypted. This requirement applies to the API fields containing encryptedData. Sensitive data is encrypted using a symmetric session (one-time-use) key. The symmetric session key is then wrapped with an RSA Public Key supplied by Mastercard during API setup phase (the Customer Encryption Key). <br>  Java Client Encryption Library available on [GitHub](https://github.com/Mastercard/client-encryption-java) 
 *
 * OpenAPI spec version: 1.2.10
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.wallee.sdk.mdes.model;

import com.google.gson.annotations.SerializedName;
import java.util.Objects;
import com.wallee.sdk.mdes.model.AccountHolderData;
import com.wallee.sdk.mdes.model.CardAccountDataOutbound;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * TokenDetailData
 */

public class TokenDetailData {
  @SerializedName("accountHolderData")
  private AccountHolderData accountHolderData = null;

  @SerializedName("cardAccountData")
  private CardAccountDataOutbound cardAccountData = null;

  @SerializedName("paymentAccountReference")
  private String paymentAccountReference = null;

  public TokenDetailData accountHolderData(AccountHolderData accountHolderData) {
    this.accountHolderData = accountHolderData;
    return this;
  }

   /**
   * Account holder information. Present in tokenize response if supported by the Token Requestor, if using a pushAccountReceipt and if there is account holder data associated with the push account receipt in case that the issuer decision is APPROVED.. 
   * @return accountHolderData
  **/
  public AccountHolderData getAccountHolderData() {
    return accountHolderData;
  }

  public void setAccountHolderData(AccountHolderData accountHolderData) {
    this.accountHolderData = accountHolderData;
  }

  public TokenDetailData cardAccountData(CardAccountDataOutbound cardAccountData) {
    this.cardAccountData = cardAccountData;
    return this;
  }

   /**
   * The credit or debit card information for the account that is being tokenized.  Present in tokenize response if supported by the Token Requestor, if using a pushAccountReceipt and if there is a card account associated with the pushAccountReceipt in case that the issuer decision is not DECLINED. 
   * @return cardAccountData
  **/
  public CardAccountDataOutbound getCardAccountData() {
    return cardAccountData;
  }

  public void setCardAccountData(CardAccountDataOutbound cardAccountData) {
    this.cardAccountData = cardAccountData;
  }

  public TokenDetailData paymentAccountReference(String paymentAccountReference) {
    this.paymentAccountReference = paymentAccountReference;
    return this;
  }

   /**
   * \&quot;The unique account reference assigned to the PAN. Conditionally returned if the Token Requestor has opted to receive PAR and providing PAR is assigned by Mastercard or the Issuer provides PAR in the authorization message response.    __Max Length:__ - 29\&quot; 
   * @return paymentAccountReference
  **/
  public String getPaymentAccountReference() {
    return paymentAccountReference;
  }

  public void setPaymentAccountReference(String paymentAccountReference) {
    this.paymentAccountReference = paymentAccountReference;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    TokenDetailData tokenDetailData = (TokenDetailData) o;
    return Objects.equals(this.accountHolderData, tokenDetailData.accountHolderData) &&
        Objects.equals(this.cardAccountData, tokenDetailData.cardAccountData) &&
        Objects.equals(this.paymentAccountReference, tokenDetailData.paymentAccountReference);
  }

  @Override
  public int hashCode() {
    return Objects.hash(accountHolderData, cardAccountData, paymentAccountReference);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class TokenDetailData {\n");
    
    sb.append("    accountHolderData: ").append(toIndentedString(accountHolderData)).append("\n");
    sb.append("    cardAccountData: ").append(toIndentedString(cardAccountData)).append("\n");
    sb.append("    paymentAccountReference: ").append(toIndentedString(paymentAccountReference)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }
  
}
