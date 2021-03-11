package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IDOR extends VulTaskImpl {

    public IDOR(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo, int rows) {
        super(helpers, callbacks, log, messageInfo, rows);
    }

    @Override
    public VulResult run() {
        String message = "";
        //返回信息
        IHttpService iHttpService = messageInfo.getHttpService();
        IResponseInfo analyzeResponse = this.helpers.analyzeResponse(messageInfo.getResponse());
        String response_info = new String(messageInfo.getResponse());
        String rep_body = response_info.substring(analyzeResponse.getBodyOffset());
        short status_code = analyzeResponse.getStatusCode();
        List<String> response_header_list = analyzeResponse.getHeaders();

        //请求信息
        IRequestInfo analyzeRequest = this.helpers.analyzeRequest(messageInfo);
        String request_info = new String(messageInfo.getRequest());
        List<String> request_header_list = analyzeRequest.getHeaders();

        //返回上面板信息
        String host = iHttpService.getHost();
        String path = analyzeRequest.getUrl().getPath();
        //String param = param_list.toString();
        String method = analyzeRequest.getMethod();
        int id = rows + 1;
        IHttpRequestResponse messageInfo_r = null;
        short status = status_code;

        //获取body信息
        String messageBody = request_info.substring(analyzeRequest.getBodyOffset());
        byte[] request_body = messageBody.getBytes();

        //1、删除cookie，重新发起请求，与原始请求状态码一致则可能存在未授权访问
        List<String> new_headers1 = new ArrayList<String>();
        for (String header :
                request_header_list) {
            //删除cookie
            if (header.toLowerCase(Locale.ROOT).startsWith("cookie")) {
                continue;
            }else {
                new_headers1.add(header);
            }
        }
        //新的请求包
        byte[] req = this.helpers.buildHttpMessage(new_headers1, request_body);
//        callbacks.printOutput(new String(req));
        IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req);
        //新的返回包
        IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
        String response_info1 = new String(messageInfo1.getResponse());
        String rep1_body = response_info1.substring(analyzeResponse1.getBodyOffset());
        status = analyzeResponse1.getStatusCode();

        //如果状态码相同则可能存在问题
        if (status_code == analyzeResponse1.getStatusCode()
                && rep_body.equalsIgnoreCase(rep1_body)) {
            message = "IDOR";
            messageInfo_r = messageInfo1;
        }

        if (!message.equalsIgnoreCase("")){
            logAdd(id, messageInfo_r, host, path, method, status, message);
        }

        return new VulResult(message, status_code, messageInfo_r, path, host);
    }
}
