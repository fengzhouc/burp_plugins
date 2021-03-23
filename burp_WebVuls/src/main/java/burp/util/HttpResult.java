package burp.util;

import burp.IHttpRequestResponse;

public class HttpResult {

    public final IHttpRequestResponse httpRequestResponse;
    public final String Url;

    public HttpResult(String url, IHttpRequestResponse httpRequestResponse) {
        this.Url = url;
        this.httpRequestResponse = httpRequestResponse;

    }
}
