package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.List;

public class XssReflect extends VulTaskImpl {

    public XssReflect(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、所有参数都添加特使flag
         * 2、然后检查响应头是否存在flag
         * */
        callbacks.printError("XssReflect checking");
        String xssflag = "_xssflag";
        // 后缀检查，静态资源不做测试
        if (isStaticSource(path)){
            return null;
        }
        payloads = loadPayloads("/payloads/XssReflect.bbm");

        //反射型只测查询参数
        String query = request_header_list.get(0);
        if (query.contains("?"))
        {
            String queryParam = query.split("\\?")[1];
            String[] qs = queryParam.split("&");
            StringBuilder stringBuilder = new StringBuilder();
            for (String param : qs){
                stringBuilder.append(param).append(xssflag).append("&");
            }
            List<String> new_headers = request_header_list;
            String header_first = "";
            header_first = query.replace(queryParam, stringBuilder.toString());
            //替换请求包中的url
            new_headers.remove(0);
            new_headers.add(0, header_first);

            //新的请求包
            callbacks.printError("XssReflect-before: \n" + new_headers.toString());
            IHttpRequestResponse messageInfo1 = requester.send(this.iHttpService, new_headers, request_body_byte);
            callbacks.printError("XssReflect-end: \n" + new String(messageInfo1.getResponse()));

            //以下进行判断
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            String resp = new String(messageInfo1.getResponse());
            String resp1_body = resp.substring(analyzeResponse1.getBodyOffset());
            status = analyzeResponse1.getStatusCode();

            // 检查响应中是否存在flag
            if (resp1_body.contains(xssflag)) {
                result = logAdd(messageInfo1, host, path, method, status, "XssReflect", payloads);
            }
        }
        callbacks.printError("XssReflect checked");
        return result;
    }
}
