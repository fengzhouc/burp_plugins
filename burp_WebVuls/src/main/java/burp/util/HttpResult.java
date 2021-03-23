package burp.util;

import burp.IHttpRequestResponse;

public class HttpResult {

    public final String message;
    public final short status;
    public final IHttpRequestResponse httpRequestResponse;
    public final String host;
    public final String path;
    public final String method;


    public HttpResult(String message, short status, IHttpRequestResponse httpRequestResponse, String path, String host, String method) {
        this.message = message;
        this.status = status;
        this.httpRequestResponse = httpRequestResponse;
        this.host = host;
        this.path = path;
        this.method = method;

    }
}
