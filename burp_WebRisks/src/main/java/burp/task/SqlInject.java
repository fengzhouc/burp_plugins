package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
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
        callbacks.printError("SqlInject");
        String injectStr = "null";
        try {//进行编码，不然请求会错误
            injectStr = URLEncoder.encode("'\"\\\"", "UTF-8");
        } catch (UnsupportedEncodingException e) {
            callbacks.printError(e.toString());
        }

        // 后缀检查，静态资源不做测试
        if (isStaticSource(path)){
            return null;
        }
        payloads = loadPayloads("/payloads/SqlInject.bbm");
        //反射型只测查询参数
        String query = request_header_list.get(0);
        if (query.contains("?"))
        {
            String queryParam = query.split("\\?")[1];
            List<String> new_headers = request_header_list;
            String header_first = "";
            header_first = query.replace(queryParam, createFormBody(queryParam, injectStr));
            //替换请求包中的url
            new_headers.remove(0);
            new_headers.add(0, header_first);

            //新的请求包
            callbacks.printError("before: " + new_headers.toString());
            IHttpRequestResponse messageInfo1 = BurpExtender.requester.send(this.iHttpService, new_headers, request_body_byte);
            callbacks.printError("end: " + messageInfo1.getHttpService().toString());
            //以下进行判断
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            String resp = new String(messageInfo1.getResponse());
            String resp1_body = resp.substring(analyzeResponse1.getBodyOffset());
            status = analyzeResponse1.getStatusCode();

            // 检查响应中是否存在flag
            if (resp1_body.contains("SQL")) {
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
            String req_body = "";
            switch (contentype){
                case "json":
                    req_body = createJsonBody(request_body_str, injectStr);
                    break;
                case "form":
                    req_body = createFormBody(request_body_str, injectStr);
                    break;
            }
            //新的请求包
            callbacks.printError("before: " + request_header_list.toString());
            IHttpRequestResponse messageInfo1 = BurpExtender.requester.send(this.iHttpService, request_header_list, req_body.getBytes());
            callbacks.printError("end: " + messageInfo1.getHttpService().toString());
            //以下进行判断
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            String resp = new String(messageInfo1.getResponse());
            String resp1_body = resp.substring(analyzeResponse1.getBodyOffset());
            status = analyzeResponse1.getStatusCode();

            // 检查响应中是否存在flag
            // TODO 关键字是否全
            if (resp1_body.contains("SQL")) {
                result = logAdd(messageInfo1, host, path, method, status, "SqlInject", payloads);
            }
        }

        return result;
    }

}
