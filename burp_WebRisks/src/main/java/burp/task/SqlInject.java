package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.ArrayList;
import java.util.List;

public class SqlInject extends VulTaskImpl {

    public SqlInject(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、所有参数都添加特殊字符
         * 2、然后检查响应是否不同或者存在关键字
         * */
        String injectStr = helpers.urlEncode("'\"\\\"");

        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (isStaticSource(path, add)){
            return null;
        }
        payloads = loadPayloads("/payloads/SqlInject.bbm");
        //反射型只测查询参数
        String req_line = request_header_list.get(0);
        if (query != null)
        {
            List<String> new_headers = request_header_list;
            String header_first = "";
            header_first = req_line.replace(query, createFormBody(query, injectStr));
            //替换请求包中的url
            new_headers.remove(0);
            new_headers.add(0, header_first);

            //新的请求包
            callbacks.printError("sqlinject-query: " + header_first);
            IHttpRequestResponse messageInfo1 = requester.send(this.iHttpService, new_headers, request_body_byte);
            //以下进行判断
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            String resp = new String(messageInfo1.getResponse());
            String resp1_body = resp.substring(analyzeResponse1.getBodyOffset());
            status = analyzeResponse1.getStatusCode();

            // 检查响应中是否存在flag
            if (resp1_body.contains("SQL syntax")) {
                result = logAdd(messageInfo1, host, path, method, status, "SqlInject", payloads);
            }
        }
        //如果有body参数，需要多body参数进行测试
        if (request_body_str.length() > 0){
            String contentype = "";
            for (String header :
                    request_header_list) {
                if (header.contains("json")){
                    contentype = "json";
                }else if (header.contains("form")){
                    contentype = "form";
                }
            }
            String req_body = request_body_str;
            switch (contentype){
                case "json":
                    req_body = createJsonBody(request_body_str, injectStr);
                    break;
                case "form":
                    req_body = createFormBody(request_body_str, injectStr);
                    break;
            }
            //新的请求包
            callbacks.printError("sqlinject-body: " + path + "\n" + req_body);
            IHttpRequestResponse messageInfo1 = requester.send(this.iHttpService, request_header_list, req_body.getBytes());
            //以下进行判断
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            String resp = new String(messageInfo1.getResponse());
            String resp1_body = resp.substring(analyzeResponse1.getBodyOffset());
            status = analyzeResponse1.getStatusCode();

            // 检查响应中是否存在flag
            // TODO 关键字是否全
            if (resp1_body.contains("SQL syntax")) {
                result = logAdd(messageInfo1, host, path, method, status, "SqlInject", payloads);
            }
        }
        callbacks.printError("SqlInject checked");
        return result;
    }

}
