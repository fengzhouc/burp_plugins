package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class Jsonp extends VulTaskImpl {

    public Jsonp(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo, int rows) {
        super(helpers, callbacks, log, messageInfo, rows);
    }

    @Override
    public VulResult run() {
        String message = "";
        //返回信息
        IHttpService iHttpService = messageInfo.getHttpService();
        IResponseInfo analyzeResponse = this.helpers.analyzeResponse(messageInfo.getResponse());
        String response_info = new String(messageInfo.getResponse());
        String rep_body = response_info.substring(analyzeResponse.getBodyOffset());
        short status_code = analyzeResponse.getStatusCode();
        List<String> response_header_list = analyzeResponse.getHeaders();

        //请求信息
        IRequestInfo analyzeRequest = this.helpers.analyzeRequest(messageInfo);
        String request_info = new String(messageInfo.getRequest());
        List<String> request_header_list = analyzeRequest.getHeaders();

        //返回上面板信息
        String host = iHttpService.getHost();
        String path = analyzeRequest.getUrl().getPath();
        String method = analyzeRequest.getMethod();
        int id = rows + 1;
        IHttpRequestResponse messageInfo_r = null;
        short status = status_code;

        //获取body信息
        String messageBody = request_info.substring(analyzeRequest.getBodyOffset());
        byte[] request_body = messageBody.getBytes();

        //1.请求的url中含Jsonp敏感参数
        String query = request_header_list.get(0);
        if (query.contains("callback=")
                || query.contains("cb=")
                || query.contains("jsonp")
                || query.contains("json=")
                || query.contains("call="))
        {
            log.add(new BurpExtender.LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo),
                    host, path, method, status, "jsonp"));
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
            byte[] req = this.helpers.buildHttpMessage(new_headers, request_body);
//           callbacks.printOutput(new String(req));
            IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req);

            //新的返回包
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            String response_info1 = new String(messageInfo1.getResponse());
            String rep1_body = response_info1.substring(analyzeResponse1.getBodyOffset());
            status = analyzeResponse1.getStatusCode();

            // 如果返回body中有请求传入的函数qwert，则可能存在jsonp
            if (rep1_body.contains("qwert"))
            {	//id response host path status
                log.add(new BurpExtender.LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo1),
                        host, path, method, status, "jsonp"));
            }
        }

        return new VulResult(message, status_code, messageInfo_r, path, host);
    }
}
