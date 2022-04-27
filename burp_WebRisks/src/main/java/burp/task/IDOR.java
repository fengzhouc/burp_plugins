package burp.task;

import burp.*;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class IDOR extends VulTaskImpl {

    public IDOR(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 未授权访问
         * 检测逻辑
         * 1、删除cookie发起请求
         * */
        // 后缀检查，静态资源不做测试
        if (isStaticSource(path)){
            return null;
        }

        //1、删除cookie，重新发起请求，与原始请求状态码一致则可能存在未授权访问
        // 只测试原本有cookie的请求
        List<String> new_headers1 = new ArrayList<String>();
        boolean hasCookie = false;
        for (String header :
                request_header_list) {
            //删除cookie
            String key = BurpExtender.cookie.split(":")[0];
            if (header.toLowerCase(Locale.ROOT).startsWith(key.toLowerCase(Locale.ROOT))) {
                hasCookie = true;
            }else {
                new_headers1.add(header);
            }
        }
        // 请求没有cookie,则不测试
        if (!hasCookie){
            return null;
        }
        //新的请求包
        IHttpRequestResponse messageInfo1 = BurpExtender.requester.send(this.iHttpService, new_headers1, request_body_byte);
        //新的返回包
        IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
        String response_info1 = new String(messageInfo1.getResponse());
        String rep1_body = response_info1.substring(analyzeResponse1.getBodyOffset());
        status = analyzeResponse1.getStatusCode();

        //如果状态码相同则可能存在问题
        if (status_code == analyzeResponse1.getStatusCode()
                && resp_body_str.equalsIgnoreCase(rep1_body)) {
            message = "IDOR";
            messageInfo_r = messageInfo1;
        }

        if (!message.equalsIgnoreCase("")){
            result = logAdd(messageInfo_r, host, path, method, status, message, payloads);
        }

        return result;
    }
}
