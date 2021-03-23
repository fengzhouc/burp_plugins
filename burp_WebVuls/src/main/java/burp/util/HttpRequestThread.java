package burp.util;

import burp.*;

import java.util.List;

public class HttpRequestThread implements Runnable {

    public IExtensionHelpers helpers;
    public IBurpExtenderCallbacks callbacks;
    public IHttpRequestResponse messageInfo;
    public byte[] poc;
    public HttpResult resulemessageInfo = null;

    public HttpRequestThread(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, IHttpRequestResponse messageInfo, byte[] body){
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.messageInfo = messageInfo;
        this.poc = body;
    }

    @Override
    public void run() {
        //返回信息
        IHttpService iHttpService = messageInfo.getHttpService();
        IResponseInfo analyzeResponse = helpers.analyzeResponse(messageInfo.getResponse());
        short status_code = analyzeResponse.getStatusCode();

        //请求信息
        IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
        List<String> request_header_list = analyzeRequest.getHeaders();

        //返回上面板信息
        String url = helpers.analyzeRequest(messageInfo).getUrl().toString();
        IHttpRequestResponse messageInfo;
        short status = status_code;

        //新的请求包
        byte[] req = helpers.buildHttpMessage(request_header_list, this.poc);
//        callbacks.printOutput(new String(req));
        messageInfo = callbacks.makeHttpRequest(iHttpService, req);
        resulemessageInfo = new HttpResult(url, messageInfo);
    }

    public HttpResult getResulemessageInfo(){
        return resulemessageInfo;
    }
}
