package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.ArrayList;
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
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (isStaticSource(path, add)){
            return null;
        }
        payloads = loadPayloads("/payloads/XssReflect.bbm");

        //反射型只测查询参数
        String req_line = request_header_list.get(0);
        if (query != null)
        {
            List<String> new_headers = request_header_list;
            String header_first = "";
            header_first = req_line.replace(query, createFormBody(query, xssflag));
            //替换请求包中的url
            new_headers.remove(0);
            new_headers.add(0, header_first);

            //新的请求包
            IHttpRequestResponse messageInfo1 = requester.send(this.iHttpService, new_headers, request_body_byte);

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
