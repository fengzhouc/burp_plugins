package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.List;
import java.util.Locale;

public class IndexOf extends VulTaskImpl {
    // 目录浏览漏洞

    public IndexOf(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
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

        //请求信息
        IRequestInfo analyzeRequest = this.helpers.analyzeRequest(messageInfo);
        List<String> request_header_list = analyzeRequest.getHeaders();

        //返回上面板信息
        String host = iHttpService.getHost();
        String path = analyzeRequest.getUrl().getPath();
        String method = analyzeRequest.getMethod();
        IHttpRequestResponse messageInfo_r = messageInfo;

        // 检查是否存在目录浏览
        List<String> new_headers = request_header_list;
        String header_first = "";

        //url有参数
        String query = request_header_list.get(0);
        header_first = query.replace("?", "?redirect=http://evil.com/test&" +
                "redirect_url=http://evil.com/test&" +
                "redirect_uri=http://evil.com/test&" +
                "callback=http://evil.com/test&" +
                "url=http://evil.com/test&" +
                "goto=http://evil.com/test&");

        new_headers.remove(0);
        new_headers.add(0, header_first);

        //新的请求包
        byte[] req = this.helpers.buildHttpMessage(new_headers, new byte[]{});
        IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req);
        //新的返回包
        IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
        //获取body信息
        String messageBody = new String(messageInfo1.getResponse()).substring(analyzeResponse1.getBodyOffset());
        if (messageBody.contains("Index of")){
            message = "Index of /";
        }

        if (!message.equalsIgnoreCase("")){
            result = logAdd(messageInfo_r, host, path, method, status_code, message, "");
        }

        return result;
    }
}
