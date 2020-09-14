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


package com.wallee.sdk.trid.api;

import com.wallee.sdk.trid.ApiCallback;
import com.wallee.sdk.trid.ApiClient;
import com.wallee.sdk.trid.ApiException;
import com.wallee.sdk.trid.ApiResponse;
//import com.wallee.sdk.trid.Configuration;
import com.wallee.sdk.trid.Pair;
import com.wallee.sdk.trid.ProgressRequestBody;
import com.wallee.sdk.trid.ProgressResponseBody;

import com.google.gson.reflect.TypeToken;

import java.io.IOException;


import com.wallee.sdk.trid.model.RequestTokenRequestorResponseSchema;
import com.wallee.sdk.trid.model.UpdateTokenRequestorRequestSchema;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BatchUpdateTokenRequestorsApi {
    private ApiClient apiClient;

//    public BatchUpdateTokenRequestorsApi() {
//        this(Configuration.getDefaultApiClient());
//    }

    public BatchUpdateTokenRequestorsApi(ApiClient apiClient) {
        this.apiClient = apiClient;
    }

    public ApiClient getApiClient() {
        return apiClient;
    }

    public void setApiClient(ApiClient apiClient) {
        this.apiClient = apiClient;
    }

    /**
     * Build call for tokenRequestorsBatchesPUT
     * @param body Update Token Requestor accepts a request containing updated information about a token requestor.   The request will be validated and the caller authorized.  A positive response indicates that the request was received for processing. (required)
     * @param progressListener Progress listener
     * @param progressRequestListener Progress request listener
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     */
    public com.squareup.okhttp.Call tokenRequestorsBatchesPUTCall(UpdateTokenRequestorRequestSchema body, final ProgressResponseBody.ProgressListener progressListener, final ProgressRequestBody.ProgressRequestListener progressRequestListener) throws ApiException {
        Object localVarPostBody = body;
        
        // create path and map variables
        String localVarPath = "/token-requestors/batches";

        List<Pair> localVarQueryParams = new ArrayList<Pair>();

        Map<String, String> localVarHeaderParams = new HashMap<String, String>();

        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = apiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) localVarHeaderParams.put("Accept", localVarAccept);

        final String[] localVarContentTypes = {
            "application/json"
        };
        final String localVarContentType = apiClient.selectHeaderContentType(localVarContentTypes);
        localVarHeaderParams.put("Content-Type", localVarContentType);

        if(progressListener != null) {
            apiClient.getHttpClient().networkInterceptors().add(new com.squareup.okhttp.Interceptor() {
                @Override
                public com.squareup.okhttp.Response intercept(com.squareup.okhttp.Interceptor.Chain chain) throws IOException {
                    com.squareup.okhttp.Response originalResponse = chain.proceed(chain.request());
                    return originalResponse.newBuilder()
                    .body(new ProgressResponseBody(originalResponse.body(), progressListener))
                    .build();
                }
            });
        }

        String[] localVarAuthNames = new String[] {  };
        return apiClient.buildCall(localVarPath, "PUT", localVarQueryParams, localVarPostBody, localVarHeaderParams, localVarFormParams, localVarAuthNames, progressRequestListener);
    }
    
    @SuppressWarnings("rawtypes")
    private com.squareup.okhttp.Call tokenRequestorsBatchesPUTValidateBeforeCall(UpdateTokenRequestorRequestSchema body, final ProgressResponseBody.ProgressListener progressListener, final ProgressRequestBody.ProgressRequestListener progressRequestListener) throws ApiException {
        
        // verify the required parameter 'body' is set
        if (body == null) {
            throw new ApiException("Missing the required parameter 'body' when calling tokenRequestorsBatchesPUT(Async)");
        }
        
        
        com.squareup.okhttp.Call call = tokenRequestorsBatchesPUTCall(body, progressListener, progressRequestListener);
        return call;

        
        
        
        
    }

    /**
     * TokenRequestorsBatches_PUT
     * 
     * @param body Update Token Requestor accepts a request containing updated information about a token requestor.   The request will be validated and the caller authorized.  A positive response indicates that the request was received for processing. (required)
     * @return RequestTokenRequestorResponseSchema
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     */
    public RequestTokenRequestorResponseSchema tokenRequestorsBatchesPUT(UpdateTokenRequestorRequestSchema body) throws ApiException {
        ApiResponse<RequestTokenRequestorResponseSchema> resp = tokenRequestorsBatchesPUTWithHttpInfo(body);
        return resp.getData();
    }

    /**
     * TokenRequestorsBatches_PUT
     * 
     * @param body Update Token Requestor accepts a request containing updated information about a token requestor.   The request will be validated and the caller authorized.  A positive response indicates that the request was received for processing. (required)
     * @return ApiResponse&lt;RequestTokenRequestorResponseSchema&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     */
    public ApiResponse<RequestTokenRequestorResponseSchema> tokenRequestorsBatchesPUTWithHttpInfo(UpdateTokenRequestorRequestSchema body) throws ApiException {
        com.squareup.okhttp.Call call = tokenRequestorsBatchesPUTValidateBeforeCall(body, null, null);
        Type localVarReturnType = new TypeToken<RequestTokenRequestorResponseSchema>(){}.getType();
        return apiClient.execute(call, localVarReturnType);
    }

    /**
     * TokenRequestorsBatches_PUT (asynchronously)
     * 
     * @param body Update Token Requestor accepts a request containing updated information about a token requestor.   The request will be validated and the caller authorized.  A positive response indicates that the request was received for processing. (required)
     * @param callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     */
    public com.squareup.okhttp.Call tokenRequestorsBatchesPUTAsync(UpdateTokenRequestorRequestSchema body, final ApiCallback<RequestTokenRequestorResponseSchema> callback) throws ApiException {

        ProgressResponseBody.ProgressListener progressListener = null;
        ProgressRequestBody.ProgressRequestListener progressRequestListener = null;

        if (callback != null) {
            progressListener = new ProgressResponseBody.ProgressListener() {
                @Override
                public void update(long bytesRead, long contentLength, boolean done) {
                    callback.onDownloadProgress(bytesRead, contentLength, done);
                }
            };

            progressRequestListener = new ProgressRequestBody.ProgressRequestListener() {
                @Override
                public void onRequestProgress(long bytesWritten, long contentLength, boolean done) {
                    callback.onUploadProgress(bytesWritten, contentLength, done);
                }
            };
        }

        com.squareup.okhttp.Call call = tokenRequestorsBatchesPUTValidateBeforeCall(body, progressListener, progressRequestListener);
        Type localVarReturnType = new TypeToken<RequestTokenRequestorResponseSchema>(){}.getType();
        apiClient.executeAsync(call, localVarReturnType, callback);
        return call;
    }
}
