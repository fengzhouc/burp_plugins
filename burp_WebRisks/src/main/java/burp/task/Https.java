package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.List;
import java.util.Locale;

public class Https extends VulTaskImpl {
    // 检查是否使用https

    public Https(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        String message = "";
        VulResult result = null;
        //返回信息
        IHttpService iHttpService = messageInfo.getHttpService();
        IResponseInfo analyzeResponse = this.helpers.analyzeResponse(messageInfo.getResponse());
        short status_code = analyzeResponse.getStatusCode();
        List<String> response_header_list = analyzeResponse.getHeaders();

        //请求信息
        IRequestInfo analyzeRequest = this.helpers.analyzeRequest(messageInfo);

        //返回上面板信息
        String host = iHttpService.getHost();
        String path = analyzeRequest.getUrl().getPath();
        String method = analyzeRequest.getMethod();
        IHttpRequestResponse messageInfo_r = messageInfo;

        String protocol = iHttpService.getProtocol();
        if (!protocol.toLowerCase(Locale.ROOT).startsWith("https")){
            message = "no use https";
        }


        if (!message.equalsIgnoreCase("")){
            result = logAdd(messageInfo_r, host, path, method, status_code, message, "");
        }

        return result;
    }
}
