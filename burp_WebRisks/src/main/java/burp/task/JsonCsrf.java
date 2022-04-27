package burp.task;

import burp.*;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class JsonCsrf extends VulTaskImpl {

    public JsonCsrf(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、jsonCsrf：修改content-type为form表单的
         *   （1）检查响应头中是否包含Access-Control-Allow-Credentials且为true
         *   （2）再检查Access-Control-Allow-Origin是否为*
         *   （3）不满足（2）则修改/添加请求头Origin为http://evil.com，查看响应头Access-Control-Allow-Origin的值是否是http://evil.com
         * */
        // 后缀检查，静态资源不做测试
        if (isStaticSource(path)){
            return null;
        }

        /*
         * 1、请求头包含application/json
         */
        if (check(request_header_list, "application/json") != null) {
            List<String> new_headers = request_header_list;
            List<String> new_headers1 = new ArrayList<String>();
            String CT = "Content-Type: application/x-www-form-urlencoded";
            //新请求修改content-type
            boolean hasCT = false;
            for (String header :
                    new_headers) {
                if (header.toLowerCase(Locale.ROOT).contains("content-type")) {
                    header = header.replace("application/json", "application/x-www-form-urlencoded");
                    hasCT = true;
                }
                new_headers1.add(header);
            }
            //如果请求头中没有CT，则添加一个
            if (!hasCT) {
                new_headers1.add(CT);
            }

            if (!method.equalsIgnoreCase("get")) {
                //新的请求包:content-type
                IHttpRequestResponse messageInfo1 = BurpExtender.requester.send(this.iHttpService, new_headers1, request_body_byte);
                //新的返回包
                IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
                String response_info1 = new String(messageInfo1.getResponse());
                String rep1_body = response_info1.substring(analyzeResponse1.getBodyOffset());
                status = analyzeResponse1.getStatusCode();

                //如果状态码相同则可能存在问题
                if (status_code == analyzeResponse1.getStatusCode()
                        && resp_body_str.equalsIgnoreCase(rep1_body)) {
                    message = "JsonCsrf";
                    messageInfo_r = messageInfo1;
                }
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


                    //新的请求包:ORIGIN
                    byte[] req = this.helpers.buildHttpMessage(new_headers1, request_body_byte);
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
                            messageInfo_r = messageInfo1;
                        }else {
                            message += " & CORS Bypass";
                            messageInfo_r = messageInfo1;
                        }
                    }
                }
            }
        }
        if (!message.equalsIgnoreCase("")){
            result = logAdd(messageInfo_r, host, path, method, status, message, payloads);
        }

        return result;
    }
}
