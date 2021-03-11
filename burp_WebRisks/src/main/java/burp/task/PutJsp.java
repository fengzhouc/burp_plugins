package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class PutJsp extends VulTaskImpl {

    public PutJsp(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo, int rows) {
        super(helpers, callbacks, log, messageInfo, rows);
    }

    @Override
    public VulResult run() {
        /* CVE-2017-12615 tomcat 7.0.0 to 7.0.79
         * */
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
        String method = analyzeRequest.getMethod();
        int id = rows + 1;
        IHttpRequestResponse messageInfo_r = null;
        short status = status_code;

        //获取body信息
        String messageBody = request_info.substring(analyzeRequest.getBodyOffset());
        byte[] request_body = messageBody.getBytes();
        //修改header
        List<String> new_headers1 = request_header_list;
        new_headers1.remove(0);
        new_headers1.add(0, "OPTIONS / HTTP/1.1");

        //新的请求包
        byte[] req = this.helpers.buildHttpMessage(new_headers1, request_body);
        IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req);
        //新的返回包
        IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
        List<String> response1_header_list = analyzeResponse1.getHeaders();

        String allowHeader = check(response1_header_list, "Allow:");
        if (allowHeader != null && allowHeader.toLowerCase(Locale.ROOT).contains("put")){
            new_headers1.remove(0);
            new_headers1.add(0, "OPTIONS /test.jsp HTTP/1.1");

            //新的请求包
            byte[] req2 = this.helpers.buildHttpMessage(new_headers1, request_body);
            IHttpRequestResponse messageInfo2 = this.callbacks.makeHttpRequest(iHttpService, req2);
            //新的返回包
            IResponseInfo analyzeResponse2 = this.helpers.analyzeResponse(messageInfo2.getResponse());
            status = analyzeResponse2.getStatusCode();
            if (status == 201){
                message = "PutJsp";
                messageInfo_r = messageInfo2;
            }
        }


        if (!message.equalsIgnoreCase("")){
            logAdd(id, messageInfo_r, host, path, method, status, message);
        }

        return new VulResult(message, status_code, messageInfo_r, path, host);
    }
}
