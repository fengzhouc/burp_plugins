package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class SecureCookie extends VulTaskImpl {
    // 检查cookie安全属性httponly、secure

    public SecureCookie(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
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

        // 后缀检查，静态资源不做测试
        if (suffixcheck(path)){
            return null;
        }

        for (String heaser :
                response_header_list) {
                if (heaser.toLowerCase(Locale.ROOT).startsWith("Set-Cookie".toLowerCase(Locale.ROOT))) {
                    if (!heaser.toLowerCase(Locale.ROOT).contains("httponly") || !heaser.toLowerCase(Locale.ROOT).contains("secure")){
                        message += "without httponly or secure";
                    }
                }
        }

        if (!message.equalsIgnoreCase("")){
            result = logAdd(messageInfo_r, host, path, method, status_code, message, "");
        }

        return result;
    }
}
