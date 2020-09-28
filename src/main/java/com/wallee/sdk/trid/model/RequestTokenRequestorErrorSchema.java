/*
 * Token Requestor ID API
 * An API that allows On-behalf of Token Requestors such as Payment Service Providers to bulk request TRIDs for their merchants.
 *
 * OpenAPI spec version: 1.0.0
 * Contact: apisupport@mastercard.com
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package com.wallee.sdk.trid.model;

import com.google.gson.annotations.SerializedName;
import java.util.Objects;
import com.wallee.sdk.trid.model.TokenRequestorAssignmentErrors;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.ArrayList;
import java.util.List;

/**
 * RequestTokenRequestorErrorSchema
 */

public class RequestTokenRequestorErrorSchema {
  @SerializedName("errors")
  private List<TokenRequestorAssignmentErrors> errors = new ArrayList<TokenRequestorAssignmentErrors>();

  @SerializedName("responseId")
  private String responseId = null;

  public RequestTokenRequestorErrorSchema errors(List<TokenRequestorAssignmentErrors> errors) {
    this.errors = errors;
    return this;
  }

  public RequestTokenRequestorErrorSchema addErrorsItem(TokenRequestorAssignmentErrors errorsItem) {
    this.errors.add(errorsItem);
    return this;
  }

   /**
   * Get errors
   * @return errors
  **/
  public List<TokenRequestorAssignmentErrors> getErrors() {
    return errors;
  }

  public void setErrors(List<TokenRequestorAssignmentErrors> errors) {
    this.errors = errors;
  }

  public RequestTokenRequestorErrorSchema responseId(String responseId) {
    this.responseId = responseId;
    return this;
  }

   /**
   * __REQUIRED__&lt;br&gt; Unique identifier for the response.
   * @return responseId
  **/
  public String getResponseId() {
    return responseId;
  }

  public void setResponseId(String responseId) {
    this.responseId = responseId;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    RequestTokenRequestorErrorSchema requestTokenRequestorErrorSchema = (RequestTokenRequestorErrorSchema) o;
    return Objects.equals(this.errors, requestTokenRequestorErrorSchema.errors) &&
        Objects.equals(this.responseId, requestTokenRequestorErrorSchema.responseId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(errors, responseId);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class RequestTokenRequestorErrorSchema {\n");
    
    sb.append("    errors: ").append(toIndentedString(errors)).append("\n");
    sb.append("    responseId: ").append(toIndentedString(responseId)).append("\n");
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

