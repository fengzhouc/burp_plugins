package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;
import java.util.ArrayList;
import java.util.List;

public class BypassAuth extends VulTaskImpl {

    public BypassAuth(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 绕过鉴权
         * */
        String message = "";
        VulResult result = null;
        //返回信息
        IHttpService iHttpService = messageInfo.getHttpService();
        IResponseInfo analyzeResponse = this.helpers.analyzeResponse(messageInfo.getResponse());
        String response_info = new String(messageInfo.getResponse());
        String rep_body = response_info.substring(analyzeResponse.getBodyOffset());
        short status_code = analyzeResponse.getStatusCode();

        //请求信息
        IRequestInfo analyzeRequest = this.helpers.analyzeRequest(messageInfo);
        String request_info = new String(messageInfo.getRequest());
        List<String> request_header_list = analyzeRequest.getHeaders();

        //返回上面板信息
        String host = iHttpService.getHost();
        String path = analyzeRequest.getUrl().getPath();
        //String param = param_list.toString();
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

        List<String> bypass_str = new ArrayList<String>();
        bypass_str.add("/xxx/../");
        bypass_str.add("/;xxx/");
        bypass_str.add("/aaa;xxx/../");
        bypass_str.add(";");
        bypass_str.add("/./");
        bypass_str.add("////");
        bypass_str.add("%00");
        bypass_str.add("%20");

        // 将path拆解
        String[] paths = path.split("/");
        List<String> bypass_path = new ArrayList<String>();
        // 添加bypass，如:/api/test -> /api/xxx/../test/xxx/../
        for (String str :
                bypass_str) {
            StringBuilder sb = new StringBuilder();
            for (String p :
                    paths) {
                sb.append(p + str + "/");
            }
            bypass_path.add(sb.toString());
        }
        //修改api
        String query = request_header_list.get(0);
        List<String> new_headers = request_header_list;
        String header_first = "";

        for (String bypass :
                bypass_path) {
            //url有参数
            header_first = query.replace(path, bypass);

            new_headers.remove(0);
            new_headers.add(0, header_first);

            //新的请求包
            byte[] req = this.helpers.buildHttpMessage(new_headers, request_body);
            callbacks.printOutput(new String(req));
            IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req);
            //新的返回包
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            String response_info1 = new String(messageInfo1.getResponse());
            String rep1_body = response_info1.substring(analyzeResponse1.getBodyOffset());
            status = analyzeResponse1.getStatusCode();

            //如果状态码相同则可能存在问题
            if (status_code == analyzeResponse1.getStatusCode()
                    && rep_body.equalsIgnoreCase(rep1_body)) {
                message = "BypassAuth";
                messageInfo_r = messageInfo1;
            }
        }


        if (!message.equalsIgnoreCase("")){
            result = logAdd(messageInfo_r, host, path, method, status, message, "");
        }

        return result;
    }
}
