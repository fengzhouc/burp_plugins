package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class Cors extends VulTaskImpl {

    public Cors(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、cors
         *   （1）检查响应头中是否包含Access-Control-Allow-Credentials且为true
         *   （2）再检查Access-Control-Allow-Origin是否为*
         *   （3）不满足（2）则修改/添加请求头Origin为http://evil.com，查看响应头Access-Control-Allow-Origin的值是否是http://evil.com
         * */
        String decs = "";

        // 后缀检查，静态资源不做测试
        if (suffixcheck(path)){
            return null;
        }

        //新请求body
        String messageBody = request_info.substring(analyzeRequest.getBodyOffset());
        byte[] request_body = messageBody.getBytes();

        /*
         * ajax请求跨域获取数据的条件
         * 1、Access-Control-Allow-Credentials为true
         * 2、Access-Control-Allow-Origin为*或者根据origin动态设置
         */
        if (check(response_header_list, "Access-Control-Allow-Origin") != null){
            String origin = check(response_header_list, "Access-Control-Allow-Origin");
            String credentials = check(response_header_list, "Access-Control-Allow-Credentials");
            if (credentials != null && credentials.contains("true")){
                if (origin.contains("*")) {
                    message += "CORS Bypass";
                    decs = "Access-Control-Allow-Origin配置为*, 允许任意跨域请求";
                    messageInfo_r = messageInfo;
                }else {
                    List<String> new_headers = request_header_list;
                    List<String> new_headers1 = new ArrayList<String>();
                    String evilOrigin = "http://evil.com";
                    //新请求修改origin
                    for (String header :
                            new_headers) {
                        if (!header.toLowerCase(Locale.ROOT).contains("Origin".toLowerCase(Locale.ROOT))) {
                            new_headers1.add(header);
                        }
                    }
                    new_headers1.add("Origin: "+evilOrigin);


                    //新的请求包:ORIGIN
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
                        message += "CORS Bypass";
                        decs = "Access-Control-Allow-Origin根据请求头Origin, 允许任意跨域请求";
                        messageInfo_r = messageInfo1;
                    }
                }
            }
        }
        if (!message.equalsIgnoreCase("")){
            result = logAdd(messageInfo_r, host, path, method, status, message, decs);
        }

        return result;
    }
}
