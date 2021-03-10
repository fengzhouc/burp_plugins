package burp;

public class VulResult {

    final String message;
    final short status;
    final IHttpRequestResponse httpRequestResponse;
    final String host;
    final String path;

    public VulResult(String message, short status, IHttpRequestResponse httpRequestResponse, String path, String host) {
        this.message = message;
        this.status = status;
        this.httpRequestResponse = httpRequestResponse;
        this.host = host;
        this.path = path;
    }
}
