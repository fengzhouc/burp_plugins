package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.Arrays;
import java.util.List;


public class IndexOf extends VulTaskImpl {
    // 目录浏览漏洞

    public IndexOf(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        // 检查是否存在目录浏览
        List<String> new_headers = request_header_list;
        String header_first = "";

        //去掉最后一级path
        String query = request_header_list.get(0);
        String[] q = query.split("/");
        StringBuilder p = new StringBuilder();
        for (String v :
                Arrays.copyOfRange(q, 0, q.length - 1)) {
            p.append(v);
        }
        header_first = "/" + p.toString() + "/";

        new_headers.remove(0);
        new_headers.add(0, header_first);

        //新的请求包
        byte[] req = this.helpers.buildHttpMessage(new_headers, new byte[]{});
        IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req);
        //新的返回包

        IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
        //获取body信息
        String messageBody = new String(messageInfo1.getResponse()).substring(analyzeResponse1.getBodyOffset());
        if (messageBody.contains("Index of")){
            message = "Index of /";
        }

        if (!message.equalsIgnoreCase("")){
            result = logAdd(messageInfo_r, host, path, method, status_code, message, "");
        }

        return result;
    }
}
