package burp.impl;

import burp.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public abstract class VulTaskImpl {

    protected IExtensionHelpers helpers;
    protected IBurpExtenderCallbacks callbacks;
    protected List<BurpExtender.LogEntry> log;
    protected IHttpRequestResponse messageInfo;

    public VulTaskImpl(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.log = log;
        this.messageInfo = messageInfo;
    }

    /*
    * TODO 漏洞检测任务的具体逻辑
    * 大概模板, 根据需要上下文删除不必要的代码
    * String message = "";
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
        //String param = param_list.toString();
        String method = analyzeRequest.getMethod();
        int id = rows + 1;
        IHttpRequestResponse messageInfo_r = null;
        short status = status_code;
        //获取body信息
        String messageBody = request_info.substring(analyzeRequest.getBodyOffset());
        byte[] request_body = messageBody.getBytes();

        //具体逻辑 start
            List<String> new_headers1 = request_header_list;
            new_headers1.remove(0);
            new_headers1.add(0, "OPTIONS / HTTP/1.1");
            //新的请求包
            byte[] req = this.helpers.buildHttpMessage(new_headers1, request_body);
            IHttpRequestResponse messageInfo1 = this.callbacks.makeHttpRequest(iHttpService, req);
            //新的返回包
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            status = analyzeResponse1.getStatusCode();
            //结果判断
            if (status == 201){
                    message = "PutJsp";
                    messageInfo_r = messageInfo2;
             }
        //具体逻辑 end

        if (!message.equalsIgnoreCase("")){
            logAdd(id, messageInfo_r, host, path, method, status, message);
        }
        return new VulResult(message, status_code, messageInfo_r, path, host);
    * */
    public abstract VulResult run();


    //检查头部是否包含某信息
    //头部信息包含如下
    //1、请求头/响应头
    //2、首部
    protected String check(List<String> headers, String header) {
        if (null == headers) {
            return null;
        }
        for (String s : headers) {
            if (s.toLowerCase(Locale.ROOT).contains(header.toLowerCase(Locale.ROOT))) {
                return s;
            }
        }
        return null;
    }

    // 添加面板展示数据
    // 已经在列表的不添加
    protected VulResult logAdd(IHttpRequestResponse requestResponse, String host, String path, String method, Short status, String risk, String desc) {
        boolean inside = false;
        int lastRow = log.size();
        for (BurpExtender.LogEntry le :
                log) {
            if (le.Host.equalsIgnoreCase(host)
                    && le.Path.equalsIgnoreCase(path)
                    && le.Method.equalsIgnoreCase(method)
                    && le.Status.equals(status)
                    && le.Risk.equalsIgnoreCase(risk)) {
                inside = true;
                break;
            }
        }
        if (!inside) {
            log.add(new BurpExtender.LogEntry(lastRow, callbacks.saveBuffersToTempFiles(requestResponse),
                    host, path, method, status, risk, desc));
            return new VulResult(lastRow, risk, status, requestResponse, path, host);
        }
        return null;
    }

    // 后续可以持续更新这个后缀列表
    protected boolean suffixcheck(String path) {
        List<String> suffixs = new ArrayList<String>();
        suffixs.add(".js");
        suffixs.add(".css");
        suffixs.add(".gif");
        suffixs.add(".png");
        suffixs.add(".jpg");
        suffixs.add(".woff");
        suffixs.add(".ico");
        suffixs.add(".svg");
        for (String suffix :
                suffixs) {
            if (path.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }
}
