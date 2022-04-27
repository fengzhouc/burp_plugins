package burp.task;

import burp.*;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.List;

public class Redirect extends VulTaskImpl {

    public Redirect(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、检查url参数是否包含回调函数字段
         * 2、有字段则添加字段在测试
         * */
        // 后缀检查，静态资源不做测试
        if (isStaticSource(path)){
            return null;
        }

        //1.请求的url中含redirect敏感参数
        String query = request_header_list.get(0);
//        callbacks.printOutput(query);
        if (query.contains("redirect=")
                || query.contains("redirect_url=")
                || query.contains("redirect_uri=")
                || query.contains("callback=")
                || query.contains("url=")
                || query.contains("goto="))
        {
            List<String> new_headers = request_header_list;
            String header_first = "";

            //url有参数
            header_first = query.replace("?", "?redirect=http://evil.com/test&" +
                    "redirect_url=http://evil.com/test&" +
                    "redirect_uri=http://evil.com/test&" +
                    "callback=http://evil.com/test&" +
                    "url=http://evil.com/test&" +
                    "goto=http://evil.com/test&");

            new_headers.remove(0);
            new_headers.add(0, header_first);

            //新的请求包
            IHttpRequestResponse messageInfo1 = BurpExtender.requester.send(this.iHttpService, new_headers, request_body);

            //以下进行判断
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            List<String> response_header_list1 = analyzeResponse1.getHeaders();
            status = analyzeResponse1.getStatusCode();

            // 如果响应头中Location的值中是否包含传入的url http://evil.com/test，则可能存在Redirect
            for (String header :
                    response_header_list1) {
//                callbacks.printOutput(header);
                if (header.contains("evil.com")) {
                    result = logAdd(messageInfo1, host, path, method, status, "Redirect", payloads);
                }
            }
        }

        return result;
    }
}
