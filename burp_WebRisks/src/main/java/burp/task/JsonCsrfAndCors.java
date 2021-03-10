package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class JsonCsrfAndCors extends VulTaskImpl {

    public JsonCsrfAndCors(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo, int rows) {
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
        String method = analyzeRequest.getMethod();
        int id = rows + 1;
        IHttpRequestResponse messageInfo_r = null;
        short status = status_code;

        //新请求body
        String messageBody = request_info.substring(analyzeRequest.getBodyOffset());
        byte[] request_body = messageBody.getBytes();

        /*
         * 1、请求头包含application/json
         */
        if (check(request_header_list, "application/json") != null) {
            List<String> new_headers = request_header_list;
            List<String> new_headers1 = new ArrayList<String>();
            String header_first = "";
            String CT = "Content-Type: application/x-www-form-urlencoded";
            //新请求修改content-type
            boolean hasCT = false;
            for (String header :
                    new_headers) {
                if (header.toLowerCase(Locale.ROOT).contains("content-type")) {
                    header_first = header.replace("application/json", "application/x-www-form-urlencoded");
                    new_headers1.add(header_first);
                    hasCT = true;
                } else {
                    new_headers1.add(header);
                }
            }
            //如果请求头中没有CT，则添加一个
            if (!hasCT) {
                new_headers1.add(CT);
            }

            //新的请求包:content-type
            byte[] req = this.helpers.buildHttpMessage(new_headers1, request_body);
//                    callbacks.printOutput(new String(req));
            IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req);
            //新的返回包
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            String response_info1 = new String(messageInfo1.getResponse());
            String rep1_body = response_info1.substring(analyzeResponse1.getBodyOffset());
            status = analyzeResponse1.getStatusCode();

            //如果状态码相同则可能存在问题
            if (status_code == analyzeResponse1.getStatusCode()
                    && rep_body.equalsIgnoreCase(rep1_body)) {
                message = "JsonCsrf";
                messageInfo_r = messageInfo1;
            }

        }
        /*
         * 跨域获取数据的条件
         * 1、Access-Control-Allow-Credentials为true
         * 2、Access-Control-Allow-Origin为*或者根据origin动态设置
         */
        if (check(response_header_list, "Access-Control-Allow-Origin") != null){
            String origin = check(response_header_list, "Access-Control-Allow-Origin");
            String credentials = check(response_header_list, "Access-Control-Allow-Credentials");
            if (credentials != null && credentials.contains("true")){
                if (origin.contains("*")) {
                    if (message.equalsIgnoreCase("")) {
                        message += "CORS Bypass";
                    }else {
                        message += " & CORS Bypass";
                    }
                    messageInfo_r = messageInfo;
                }else {
                    List<String> new_headers = request_header_list;
                    List<String> new_headers1 = new ArrayList<String>();
                    String evilOrigin = "http://evil.com";
                    //新请求修改origin
                    for (String header :
                            new_headers) {
                        if (header.toLowerCase(Locale.ROOT).contains("Origin".toLowerCase(Locale.ROOT))) {
                            continue;
                        }else {
                            new_headers1.add(header);
                        }
                    }
                    new_headers1.add("Origin: "+evilOrigin);


                    //新的请求包:content-type
                    byte[] req = this.helpers.buildHttpMessage(new_headers1, request_body);
//                            callbacks.printOutput(new String(req));
                    IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req);
                    //新的返回包
                    IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
                    String response_info1 = new String(messageInfo1.getResponse());
                    String rep1_body = response_info1.substring(analyzeResponse1.getBodyOffset());
                    List<String> response1_header_list = analyzeResponse1.getHeaders();
                    status = analyzeResponse1.getStatusCode();

                    //如果响应中的Access-Control-Allow-Origin跟修改的origin一样，则存在跨域
                    if (check(response1_header_list, "Access-Control-Allow-Origin").contains(evilOrigin)){
                        if (message.equalsIgnoreCase("")) {
                            message += "CORS Bypass";
                        }else {
                            message += " & CORS Bypass";
                        }
                        messageInfo_r = messageInfo1;
                    }
                }
            }
        }
        if (!message.equalsIgnoreCase("")){
            log.add(new BurpExtender.LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo_r),
                    host, path, method, status, message));
        }

        return new VulResult(message, status, messageInfo_r, path, host);
    }
}
