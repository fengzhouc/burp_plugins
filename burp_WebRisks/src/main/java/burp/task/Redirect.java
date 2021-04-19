package burp.task;

import burp.*;
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
        String message = "";
        VulResult result = null;
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
        IHttpRequestResponse messageInfo_r = null;
        short status = status_code;

        // 后缀检查，静态资源不做测试
        if (suffixcheck(path)){
            return null;
        }

        //获取body信息
        String messageBody = request_info.substring(analyzeRequest.getBodyOffset());
        byte[] request_body = messageBody.getBytes();

        //1.请求的url中含redirect敏感参数
        String query = request_header_list.get(0);
//        callbacks.printOutput(query);
        if (query.contains("redirect=")
                || query.contains("redirect_url=")
                || query.contains("redirect_uri="))
        {
            List<String> new_headers = request_header_list;
            String header_first = "";

            //url有参数
            header_first = query.replace("?", "?redirect=http://evil.com/test&redirect_url=http://evil.com/test&");

            new_headers.remove(0);
            new_headers.add(0, header_first);

            //新的请求包
            byte[] req = this.helpers.buildHttpMessage(new_headers, request_body);
//           callbacks.printOutput(new String(req));
            IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req);

            //新的返回包
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            List<String> response_header_list1 = analyzeResponse1.getHeaders();
            status = analyzeResponse1.getStatusCode();

            // 如果响应头中Location的值中是否包含传入的url http://evil.com/test，则可能存在Redirect
            for (String header :
                    response_header_list1) {
//                callbacks.printOutput(header);
                if (header.contains("evil.com")) {
                    result = logAdd(messageInfo1, host, path, method, status, "Redirect");
                }
            }
        }

        return result;
    }
}
