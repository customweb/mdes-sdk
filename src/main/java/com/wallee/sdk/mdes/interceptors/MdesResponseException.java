package com.wallee.sdk.mdes.interceptors;

public class MdesResponseException extends RuntimeException {
	private static final long serialVersionUID = -795118583436148683L;
	private final int responseCode;
	private final String contentType;
	private final String responsePayload;

	public MdesResponseException(int responseCode, String contentType, String responsePayload) {
		super(generateMessage(responseCode, contentType, responsePayload));
		this.responseCode = responseCode;
		this.contentType = contentType;
		this.responsePayload = responsePayload;
	}

	private static String generateMessage(int responseCode, String contentType, String responsePayload) {
		return "Unexpected response code: " + responseCode + ", format: " + contentType + ", response: "
				+ responsePayload;
	}

	public int getResponseCode() {
		return responseCode;
	}

	public String getContentType() {
		return contentType;
	}

	public String getResponsePayload() {
		return responsePayload;
	}
}
