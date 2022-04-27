package burp.vuls;

import burp.*;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.List;
import java.util.Locale;

public class PutJsp extends VulTaskImpl {

    public PutJsp(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、options检测响应头Allow是否包含put
         * 2、包含则测试根目录的put上传
         * 3、步骤2不成功，可能是微服务，测试下一目录的options是否包含put
         * 4、包含put则测试下一级目录的put上传
         * */
        /* CVE-2017-12615 tomcat 7.0.0 to 7.0.79
         * */
        //修改header, 根目录的put上传
        List<String> new_headers1 = request_header_list;
        new_headers1.remove(0);
        new_headers1.add(0, "OPTIONS / HTTP/1.1");

        //新的请求包
        IHttpRequestResponse messageInfo1 = BurpExtender.requester.send(this.iHttpService, new_headers1, "".getBytes());
        //新的返回包
        IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
        List<String> response1_header_list = analyzeResponse1.getHeaders();

        String allowHeader = check(response1_header_list, "Allow:");
        if (allowHeader != null && allowHeader.toLowerCase(Locale.ROOT).contains("put")){
            new_headers1.remove(0);
            new_headers1.add(0, "PUT /test.jsp HTTP/1.1");

            //新的请求包
            byte[] req2 = this.helpers.buildHttpMessage(new_headers1, "TEST".getBytes());
            IHttpRequestResponse messageInfo2 = this.callbacks.makeHttpRequest(iHttpService, req2);
            //新的返回包
            IResponseInfo analyzeResponse2 = this.helpers.analyzeResponse(messageInfo2.getResponse());
            status = analyzeResponse2.getStatusCode();
            if (status == 201){
                message = "PutJsp";
                messageInfo_r = messageInfo2;
            }
        }else { //可能是微服务架构，根目录下一级是应用的路由
            //修改header
            String[] pa = path.split("/");
            if (pa.length >= 2) {
                path = "/" + pa[1];
                List<String> new_headers3 = request_header_list;
                new_headers3.remove(0);
                new_headers3.add(0, "OPTIONS "+path+" HTTP/1.1");

                //新的请求包
                byte[] req3 = this.helpers.buildHttpMessage(new_headers3, "".getBytes());
                IHttpRequestResponse messageInfo3 = this.callbacks.makeHttpRequest(iHttpService, req3);
                //新的返回包
                IResponseInfo analyzeResponse3 = this.helpers.analyzeResponse(messageInfo3.getResponse());
                List<String> response3_header_list = analyzeResponse3.getHeaders();
                String allowHeader1 = check(response3_header_list, "Allow:");
                if (allowHeader1 != null && allowHeader1.toLowerCase(Locale.ROOT).contains("put")) {
                    new_headers3.remove(0);
                    new_headers3.add(0, "PUT "+path+"/test.jsp HTTP/1.1");

                    //新的请求包
                    byte[] req4 = this.helpers.buildHttpMessage(new_headers3, "TEST".getBytes());
                    IHttpRequestResponse messageInfo4 = this.callbacks.makeHttpRequest(iHttpService, req4);
                    //新的返回包
                    IResponseInfo analyzeResponse4 = this.helpers.analyzeResponse(messageInfo4.getResponse());
                    status = analyzeResponse4.getStatusCode();
                    if (status == 201) {
                        message = "PutJsp";
                        messageInfo_r = messageInfo4;
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
