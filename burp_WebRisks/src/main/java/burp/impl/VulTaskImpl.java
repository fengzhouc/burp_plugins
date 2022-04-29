package burp.impl;

import burp.*;
import burp.util.Requester;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

public abstract class VulTaskImpl {

    protected IExtensionHelpers helpers;
    protected IBurpExtenderCallbacks callbacks;
    protected List<BurpExtender.LogEntry> log;
    protected IHttpRequestResponse messageInfo;
    //每个task的相同变量
    protected String message; //漏洞信息
    protected VulResult result; //返回结果
    protected IHttpService iHttpService; //构造新的请求包需要
    //请求信息
    protected IRequestInfo analyzeRequest; //请求对象
    protected String url; //请求的url
    protected String request_info; //完整请求信息，包含请求头
    protected List<String> request_header_list; //请求头信息
    protected String request_body_str; //请求体信息
    protected byte[] request_body_byte; //请求body
    //响应信息
    protected IResponseInfo analyzeResponse; //响应对象
    protected String response_info; //完整响应信息，包含响应头
    protected List<String> response_header_list; //响应头信息
    protected String resp_body_str; //响应体信息
    protected short status_code; //响应状态码
    //返回UI面板的信息
    protected String host;
    protected String path;
    //String param;
    protected String method;
    protected IHttpRequestResponse messageInfo_r;
    protected short status;
    protected String payloads; //payload列表，自己手动尝试

    //发包器,单例模式
    protected Requester requester;


    public VulTaskImpl(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.log = log;
        this.messageInfo = messageInfo;
        this.requester = Requester.getInstance(this.callbacks, this.helpers);

        this.message = "";
        this.result = null;
        //返回信息
        this.iHttpService = messageInfo.getHttpService();
        //请求信息
        this.analyzeRequest = this.helpers.analyzeRequest(messageInfo);
        this.url = analyzeRequest.getUrl().toString();
        this.request_info = new String(messageInfo.getRequest());
        this.request_header_list = analyzeRequest.getHeaders();
        this.request_body_str = this.request_info.substring(analyzeRequest.getBodyOffset());
        this.request_body_byte = request_body_str.getBytes();
        //响应信息
        byte[] resp = messageInfo.getResponse();
        if (resp == null){
            this.analyzeResponse = this.helpers.analyzeResponse(new byte[]{}); //响应为空则设置空，防止NullPointerException
            this.response_info = new String(new byte[]{});
        }else{
            this.analyzeResponse = this.helpers.analyzeResponse(messageInfo.getResponse());
            this.response_info = new String(messageInfo.getResponse());
            this.resp_body_str = this.response_info.substring(this.analyzeResponse.getBodyOffset());
        }
        this.response_header_list = this.analyzeResponse.getHeaders();
        this.status_code = this.analyzeResponse.getStatusCode();
        this.messageInfo_r = messageInfo; //默认赋值为原始的，避免请求不同导致的NullPointerException

        //返回上面板信息
        this.host = iHttpService.getHost();
        this.path = analyzeRequest.getUrl().getPath();
        //String param = param_list.toString();
        this.method = analyzeRequest.getMethod();
        this.status = status_code;
        this.payloads = "";
    }

    /*
    * 漏洞检测任务的具体逻辑
    * 大概模板, 根据需要上下文删除不必要的代码
    *
        // 后缀检查，静态资源不做测试
        if (isStaticSource(path)){
            return null;
        }
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
            result = logAdd(messageInfo_r, host, "/", method, status_code, message, payloads);
        }

        return result;
     **/
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
    protected VulResult logAdd(IHttpRequestResponse requestResponse, String host, String path, String method, Short status, String risk, String payloads) {
        boolean inside = false;
        int lastRow = log.size();
        for (BurpExtender.LogEntry le :
                log) {
            if (le.Host.equalsIgnoreCase(host)
                    && le.Path.equalsIgnoreCase(path)
                    && le.Method.equalsIgnoreCase(method)
//                    && le.Status.equals(status)
                    && le.Risk.equalsIgnoreCase(risk)) {
                inside = true;
                break;
            }
        }
        if (!inside) {
            log.add(new BurpExtender.LogEntry(lastRow, callbacks.saveBuffersToTempFiles(requestResponse),
                    host, path, method, status, risk, payloads));
            return new VulResult(lastRow, risk, status, requestResponse, path, host);
        }
        return null;
    }

    // 后续可以持续更新这个后缀列表
    protected boolean isStaticSource(String path) {
        List<String> suffixs = new ArrayList<String>();
        suffixs.add(".js");
        suffixs.add(".css");
        suffixs.add(".gif");
        suffixs.add(".png");
        suffixs.add(".jpg");
        suffixs.add(".woff");
        suffixs.add(".woff2");
        suffixs.add(".ico");
        suffixs.add(".svg");
        for (String suffix :
                suffixs) {
//            callbacks.printOutput(path);
            if (path.split("\\?")[0].endsWith(suffix)) { //防止查询参数影响后缀判断
                return true;
            }
        }
        return false;
    }

    //从resource中加载payloa文件
    //filepath:/com/sss/sss.bb
    protected String loadPayloads(String filepath){
        StringBuilder payloads = new StringBuilder();
        InputStream inStream = VulTaskImpl.class.getResourceAsStream(filepath);
        assert inStream != null;
        try(Scanner scanner = new Scanner(inStream)){
            while (scanner.hasNextLine()){
                payloads.append(scanner.nextLine()).append("\n");
            }
        }
        return payloads.toString();
    }

    // 解析json，然后添加注入字符
    // https://blog.csdn.net/zitong_ccnu/article/details/47375379
    protected String createJsonBody(String body, String injectStr){
        //{"key":"value","key":"value"}
        Map<String, String> map = new HashMap<String, String>();
        ObjectMapper mapper = new ObjectMapper();
        map = jsonToMap(body);
        Map<String, String> finalMap = map;
        map.replaceAll((k, v) -> finalMap.get(k) + injectStr); //replaceAll内置函数替换所有值
        try {
            return mapper.writeValueAsString(map);
        } catch (JsonProcessingException e) {
            callbacks.printError(e.toString());
        }
        return "";
    }

    private Map<String, String> jsonToMap(String json){
        Map<String, String> map = new HashMap<String, String>();
        ObjectMapper mapper = new ObjectMapper();
        try{
            map = mapper.readValue(json, new TypeReference<HashMap<String, String>>(){});
            return map;
        } catch (IOException e) {
            callbacks.printError(e.toString());
        }
        return map;
    }
    protected String createFormBody(String body, String injectStr){
        String[] qs = body.split("&");
        StringBuilder stringBuilder = new StringBuilder();
        for (String param : qs){
            stringBuilder.append(param).append(injectStr).append("&");
        }
        return stringBuilder.toString();
    }
}
