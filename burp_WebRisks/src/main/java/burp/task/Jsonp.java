package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.util.List;

public class Jsonp extends VulTaskImpl {

    public Jsonp(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、检查url参数是否包含回调函数字段
         * 2、无字段则添加字段在测试
         * */
        // 后缀检查，静态资源不做测试
        if (isStaticSource(path)){
            return null;
        }

        //1.请求的url中含Jsonp敏感参数
        String query = request_header_list.get(0);
        if (query.contains("callback=")
                || query.contains("cb=")
                || query.contains("jsonp")
                || query.contains("json=")
                || query.contains("call="))
        {
            logAdd(messageInfo, host, path, method, status, "Jsonp", payloads);
        }

        //2.url不含敏感参数,添加参数测试
        else {

            List<String> new_headers = request_header_list;
            String header_first = "";

            //url有参数
            if (query.contains("?")) {
                header_first = query.replace("?", "?call=qwert&json=qwert&callback=qwert&cb=qwert&jsonp=qwert&jsonpcallback=qwert&");
            } else {//url无参数
                header_first = query.replace(" HTTP/1.1", "?call=qwert&json=qwert&callback=qwert&cb=qwert&jsonp=qwert&jsonpcallback=qwert HTTP/1.1");
            }
            new_headers.remove(0);
            new_headers.add(0, header_first);

            //新的请求包
            IHttpRequestResponse messageInfo1 = BurpExtender.requester.send(this.iHttpService, new_headers, request_body_byte);

            //新的返回包
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            String response_info1 = new String(messageInfo1.getResponse());
            String rep1_body = response_info1.substring(analyzeResponse1.getBodyOffset());
            status = analyzeResponse1.getStatusCode();

            // 如果返回body中有请求传入的函数qwert，则可能存在jsonp
            if (rep1_body.contains("qwert"))
            {	//id response host path status
                result = logAdd(messageInfo1, host, path, method, status, "Jsonp", payloads);
            }
        }

        return result;
    }
}
