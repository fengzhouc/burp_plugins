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
        // 后缀检查，静态资源不做测试
        if (isStaticSource(path)){
            return null;
        }

        String protocol = iHttpService.getProtocol();
        if (!protocol.toLowerCase(Locale.ROOT).startsWith("https")){
            message = "no use https";
        }

        // 检查是否同时开启http/https
        byte[] req = messageInfo.getRequest();
        IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(new IHttpService() {
            @Override
            public String getHost() {
                return iHttpService.getHost();
            }

            @Override
            public int getPort() {
                return 80;
            }

            @Override
            public String getProtocol() {
                return "http";
            }
        }, req);
        //新的返回包
        try {
            byte[] resp = messageInfo1.getResponse();
            if (resp != null) {
                IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(resp);
                if (analyzeResponse1.getStatusCode() == status_code) {
                    if (!message.equalsIgnoreCase("")) {
                        message += ", and open http";
                    } else {
                        message = "open http";
                    }
                    this.messageInfo_r = messageInfo1;
                }
            }
        }catch (NullPointerException e) {
            // 连接不上则未开启http
        }

        if (!message.equalsIgnoreCase("")){
            result = logAdd(messageInfo_r, host, "/", method, status_code, message, payloads);
        }

        return result;
    }
}
