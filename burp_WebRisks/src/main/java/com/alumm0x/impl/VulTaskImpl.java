package com.alumm0x.impl;

import burp.*;

import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.OkHttpRequester;
import com.alumm0x.util.Requester;
import com.alumm0x.util.ToolsUtil;

import java.util.*;

public abstract class VulTaskImpl extends Thread {
    
    public IHttpRequestResponse requestResponse;

    // public IBurpExtenderCallbacks callbacks;
    // public IExtensionHelpers helpers;
    // public List<LogEntry> log;
    // //每个task的相同变量
    // public String message; //漏洞信息
    // protected VulResult result; //返回结果
    // public IHttpService iHttpService; //构造新的请求包需要
    // //请求信息，用作重新发包
    // protected IRequestInfo analyzeRequest; //请求对象
    // protected String url; //请求的url
    // protected String query = "";//查询参数
    // protected List<String> request_header_list; //请求头信息
    // protected String contentYtpe;
    // protected String request_body_str = ""; //请求体参数
    // protected byte[] request_body_byte; //请求体参数byte
    // public String request_info; //完整请求信息，包含请求头

    // //响应信息,用作任务的前置条件判断
    // protected IResponseInfo analyzeResponse; //响应对象
    // protected short status_code;
    // protected List<String> response_header_list; //响应头信息
    // public String resp_body_str; //响应体信息
    // protected String response_info; //完整响应信息，包含响应头

    // //返回UI面板的信息
    // public String host;
    // public String path;
    // public String method;
    // public IHttpRequestResponse messageInfo_r;
    // public short status;
    // public String payloads; //payload列表，自己手动尝试

    // //okhttp的请求信息
    // private RequestBody ok_requestBodyObj;
    // private String ok_host;
    // private String ok_path;
    // private String ok_method;
    // private String ok_url;
    // private String ok_protocol; //响应也是用这个
    // public Headers ok_reqHeaders;
    // private String ok_reqBody;
    // public byte[] ok_reqInfo;
    // //okhttp的响应信息
    // private ResponseBody ok_responseBodyObj;
    // public int ok_code;
    // private String ok_message;
    // public Headers ok_respHeaders;
    // public String ok_respBody = "";
    // public byte[] ok_respInfo;

    //发包器,单例模式
    protected Requester requester;
    protected OkHttpRequester okHttpRequester;

    public VulTaskImpl(IHttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse ;
        this.requester = Requester.getInstance(BurpExtender.callbacks, BurpExtender.helpers);
        this.okHttpRequester = OkHttpRequester.getInstance(BurpExtender.callbacks, BurpExtender.helpers);
    }

    // public void init(IHttpRequestResponse messageInfo){
    //     this.messageInfo = messageInfo;

    //     this.message = "";
    //     this.result = null;
    //     //返回信息
    //     this.iHttpService = messageInfo.getHttpService();
    //     //请求信息
    //     this.analyzeRequest = this.helpers.analyzeRequest(messageInfo);
    //     String q = analyzeRequest.getUrl().getQuery();
    //     if (q != null) {
    //         this.query = q;
    //         this.url = analyzeRequest.getUrl().toString().split("\\?")[0]; //默认带查询参数的，去掉参数参数
    //     }else {
    //         this.url = analyzeRequest.getUrl().toString(); //默认带查询参数的，去掉参数参数
    //     }
    //     this.request_info = new String(messageInfo.getRequest());
    //     switch (analyzeRequest.getContentType()){
    //         case 0:
    //         case 1:
    //             // byte CONTENT_TYPE_URL_ENCODED = 1;
    //             // byte CONTENT_TYPE_NONE = 0;
    //             this.contentYtpe = "application/x-www-form-urlencoded";
    //             break;
    //         case 2:
    //             //byte CONTENT_TYPE_MULTIPART = 2;
    //             this.contentYtpe = "multipart/form-data";
    //             break;
    //         case 3:
    //             //byte CONTENT_TYPE_XML = 3;
    //             this.contentYtpe = "application/xml";
    //             break;
    //         case 4:
    //             //byte CONTENT_TYPE_JSON = 4;byte CONTENT_TYPE_AMF = 5;
    //             this.contentYtpe = "application/json";
    //             break;
    //         case 5:
    //             //byte CONTENT_TYPE_AMF = 5;
    //             this.contentYtpe = "application/x-amf";
    //             break;
    //         default:
    //             //byte CONTENT_TYPE_UNKNOWN = -1;
    //             this.contentYtpe = "UNKNOWN";
    //     }
    //     this.request_header_list = analyzeRequest.getHeaders();
    //     this.request_header_list.remove(0);//删除首行的GET / HTTP/1.1,不然okhttp会报错
    //     this.request_body_str = this.request_info.substring(analyzeRequest.getBodyOffset());
    //     this.request_body_byte = request_body_str.getBytes();
    //     //响应信息
    //     byte[] resp = messageInfo.getResponse();
    //     if (resp == null){
    //         this.analyzeResponse = this.helpers.analyzeResponse(new byte[]{}); //响应为空则设置空，防止NullPointerException
    //         this.response_info = new String(new byte[]{});
    //         this.status_code = 0;
    //         this.resp_body_str = "";
    //     }else{
    //         this.analyzeResponse = this.helpers.analyzeResponse(messageInfo.getResponse());
    //         this.status_code = this.analyzeResponse.getStatusCode();
    //         this.response_info = new String(messageInfo.getResponse());
    //         this.resp_body_str = this.response_info.substring(this.analyzeResponse.getBodyOffset());
    //     }
    //     this.response_header_list = this.analyzeResponse.getHeaders();
    //     this.messageInfo_r = messageInfo; //默认赋值为原始的，避免请求不同导致的NullPointerException

    //     //返回上面板信息
    //     this.host = this.iHttpService.getHost();
    //     this.path = this.analyzeRequest.getUrl().getPath();
    //     //String param = param_list.toString();
    //     this.method = this.analyzeRequest.getMethod();
    //     this.status = this.analyzeResponse.getStatusCode();
    //     this.payloads = "";
    // }

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
    public abstract void run();


    // //检查头部是否包含某信息
    // //头部信息包含如下
    // //1、请求头/响应头
    // //2、首部
    // public String check(List<String> headers, String header) {
    //     if (null == headers) {
    //         return null;
    //     }
    //     for (String s : headers) {
    //         if (s.toLowerCase(Locale.ROOT).startsWith(header.toLowerCase(Locale.ROOT))) {
    //             return s;
    //         }
    //     }
    //     return null;
    // }

    // 添加面板展示数据
    // 已经在列表的不添加
    // 添加synchronized防止多线程竞态
//     public synchronized VulResult logAdd(IHttpRequestResponse requestResponse, String host, String path, String method, short status, String risk, String payloads) {
//         boolean inside = false;
//         int row = log.size();
//         for (LogEntry le :
//                 log) {
//             if (le.Host.equalsIgnoreCase(host)
//                     && le.Path.equalsIgnoreCase(path)
//                     && le.Method.equalsIgnoreCase(method)
// //                    && le.Status.equals(status)
//                     && le.Risk.equalsIgnoreCase(risk)) {
//                 inside = true;
//                 break;
//             }
//         }
//         if (!inside) {
//             log.add(new LogEntry(row, callbacks.saveBuffersToTempFiles(requestResponse),
//                     host, path, method, status, risk, payloads));
//             //通知数据可能变更，刷新全表格数据，该用okhttp异步发包后，没办法同步调用fireTableRowsInserted通知刷新数据，因为一直row=lastRow
//             MainPanel.logTable.refreshTable();
//             return new VulResult(row, risk, status, requestResponse, path, host);
//         }
//         return null;
//     }
    //添加结果，将okhttp的请求信息封装成burp的类型
    // public void log(Call call){
    //     IHttpRequestResponse messageInfo_r = new HttpRequestResponseFactory();;//根据响应构造burp的IHttpRequestResponse对象
    //     messageInfo_r.setRequest(ok_reqInfo);
    //     messageInfo_r.setResponse(ok_respInfo);
    //     messageInfo_r.setHttpService(iHttpService);
    //     HttpUrl httpUrl = call.request().url();
    //     path = httpUrl.url().getPath();
    //     MainPanel.logAdd(messageInfo_r, ok_host, ok_path, ok_method, (short) ok_code, message, payloads);
    // }

    // 后续可以持续更新这个后缀列表
    protected boolean isStaticSource(String path, List<String> add) {
        List<String> suffixs = new ArrayList<String>();
        suffixs.add(".css");
        suffixs.add(".gif");
        suffixs.add(".png");
        suffixs.add(".jpg");
        suffixs.add(".jpeg");
        suffixs.add(".woff");
        suffixs.add(".woff2");
        suffixs.add(".ico");
        suffixs.add(".svg");
        suffixs.addAll(add);
        suffixs.add("image/");//image/png,image/jpg等
        suffixs.add("text/css");
        suffixs.add("application/font-wof");
        String cententtype = ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Content-type");
        for (String suffix :
                suffixs) {
            if (path.split("\\?")[0].endsWith(suffix)) { //防止查询参数影响后缀判断
                return true;
            }
            if (cententtype != null && cententtype.contains(suffix)){ //检查响应头
                return true;
            }
        }
        return false;
    }

    //从resource中加载payloa文件
    //filepath:/com/sss/sss.bb
    // protected String loadPayloads(String filepath){
    //     StringBuilder payloads = new StringBuilder();
    //     InputStream inStream = VulTaskImpl.class.getResourceAsStream(filepath);
    //     assert inStream != null;
    //     try(Scanner scanner = new Scanner(inStream)){
    //         while (scanner.hasNextLine()){
    //             payloads.append(scanner.nextLine()).append("\n");
    //         }
    //     }
    //     return payloads.toString();
    // }

    // // 解析json，然后添加注入字符
    // // https://blog.csdn.net/zitong_ccnu/article/details/47375379
    // protected String createJsonBody(String body, String injectStr){
    //     try {
    //         if (body.startsWith("{")){
    //             JSONObject jsonObject = new JSONObject(body);
    //             Map<String, Object> jsonMap = jsonObject.toMap();
    //             JsonTools jsonTools = new JsonTools();
    //             jsonTools.jsonObjInject(jsonMap, injectStr);
    //             return jsonTools.stringBuilder.toString();
    //         }else if (body.startsWith("[")){
    //             JSONArray jsonArray = new JSONArray(body);
    //             List<Object> jsonList = jsonArray.toList();
    //             JsonTools jsonTools = new JsonTools();
    //             jsonTools.jsonArrInject(jsonList, injectStr);
    //             return jsonTools.stringBuilder.toString();
    //         }
    //     } catch (Exception e) {
    //         callbacks.printError("createJsonBody:\n" + e +
    //                 "\nerrorData:\n" + body);
    //     }
    //     //非json数据直接原文返回
    //     return body;
    // }

    // protected String createFormBody(String body, String injectStr){
    //     String[] qs = body.split("&");
    //     StringBuilder stringBuilder = new StringBuilder();
    //     for (int i = 0;i<qs.length -1;i++){
    //         stringBuilder.append(qs[i]).append(injectStr).append("&");
    //     }
    //     stringBuilder.append(qs[qs.length-1]); //最后的参数不添加&
    //     return stringBuilder.toString();
    // }

    //因为okhttp的response是一次性的，使用后会导致后续使用会报空指针异常
    // public void setOkhttpMessage(Call call, Response response){
    //     //okhttp的请求信息
    //     this.ok_requestBodyObj = call.request().body();
    //     this.ok_host = call.request().url().host();
    //     this.ok_path = call.request().url().url().getPath();
    //     this.ok_method = call.request().method();
    //     this.ok_url = call.request().url().url().getPath() + "?" + call.request().url().url().getQuery();
    //     this.ok_protocol = response.protocol().toString().toUpperCase();//HTTP/1.1必须要大写
    //     this.ok_reqHeaders = call.request().headers();
    //     this.ok_reqBody = "";
    //     //okhttp的响应信息
    //     // this.ok_responseBodyObj = response.body();
    //     this.ok_code = response.code();
    //     this.ok_message = response.message();
    //     this.ok_respHeaders = response.headers();
    //     this.ok_respBody = "";
    //     try {
    //         // okhttp响应正文乱码,因为没法处理压缩内容的解码
    //         // https://wenku.baidu.com/view/6d3d3afda68da0116c175f0e7cd184254b351b68.html
    //         // https://blog.csdn.net/xx326664162/article/details/81661861?utm_medium=distribute.pc_aggpage_search_result.none-task-blog-2~aggregatepage~first_rank_ecpm_v1~rank_v31_ecpm-3-81661861-null-null.pc_agg_new_rank&utm_term=okhttp%E5%93%8D%E5%BA%94%E5%AD%97%E7%AC%A6%E4%B8%B2%E4%B9%B1%E7%A0%81&spm=1000.2123.3001.4430
    //         this.ok_respBody = Objects.requireNonNull(response.body()).string(); //只能调用一次，即关闭response,所以最后调用
    //     } catch (IOException e) {
    //         callbacks.printError("[VulTaskImpl]response.body() -> " + e.getMessage());
    //     }
    //     this.ok_reqInfo = okhttpReqToburpReq();
    //     this.ok_respInfo = okhttpRespToburpResp();

    //     callbacks.printOutput("####################Request and Response###########################\n" +
    //             "VulTaskImpl-reqInfo \n" + new String(ok_reqInfo) +
    //             "\n-----------------------------------------------\n"+
    //             "VulTaskImpl-respInfo \n" + ok_code + " " + new String(ok_respInfo)
    //     );
    // }

    //将okhttp的请求信息转换成burp的格式，以便展示
    // private byte[] okhttpReqToburpReq(){
    //     //获取requestBody
    //     Buffer buffer = new Buffer();
    //     try {//为空会报错，但是get请求体就是为空的
    //         Objects.requireNonNull(ok_requestBodyObj).writeTo(buffer);
    //         //编码设为UTF-8
    //         Charset charset = StandardCharsets.UTF_8; //默认UTF-8
    //         MediaType contentType = ok_requestBodyObj.contentType();
    //         if (contentType != null) {
    //             Charset charset0 = contentType.charset(StandardCharsets.UTF_8);
    //             if (charset0 != null){ //有些contentType是没带charset的
    //                 charset = charset0;
    //             }
    //         }
    //         //拿到requestBody
    //         ok_reqBody = buffer.readString(charset);
    //     } catch (Exception e) {
    //         //保持默认值空字符串即可
    //         callbacks.printError("[okhttpReqToburpReq] ok_reqBody charset Error -> " + e.getMessage());
    //     }

    //     StringBuilder stringBuilder = new StringBuilder();
    //     stringBuilder.append(ok_method + " " + ok_url + " " + ok_protocol).append("\r\n");
    //     //stringBuilder.append(ok_reqHeaders); // Header默认将Cookie视为敏感数据，toString会给脱敏了，所以ui上看不到cookie，但实际请求不影响
    //     for (String header : //直接改用原headers进行构造burp的展示request,官方也有提供返回明文的：Headers.toMultimap().toString()，不过数据处理比较麻烦，还是用burp原生的吧
    //             okHeadersToList(ok_reqHeaders)) {
    //         stringBuilder.append(header).append("\r\n");
    //     }
    //     stringBuilder.append("\r\n");
    //     stringBuilder.append(ok_reqBody);

    //     return stringBuilder.toString().getBytes(StandardCharsets.UTF_8);

    // }
    // //将okhttp的响应信息转换成burp的格式，以便展示
    // private byte[] okhttpRespToburpResp(){
    //     StringBuilder stringBuilder = new StringBuilder();
    //     stringBuilder.append(ok_protocol + " " + ok_code + " " + ok_message).append("\r\n");
    //     for (String header : //直接改用原headers进行构造burp的展示request,官方也有提供返回明文的：Headers.toMultimap().toString()，不过数据处理比较麻烦，还是用burp原生的吧
    //             okHeadersToList(ok_respHeaders)) {
    //         stringBuilder.append(header).append("\r\n");
    //     }
    //     stringBuilder.append("\r\n");
    //     stringBuilder.append(ok_respBody);

    //     return  stringBuilder.toString().getBytes(StandardCharsets.UTF_8);
    // }

    // //将Headers转换成List，使用toMultimap，解决敏感字段被okhttp脱敏的问题
    // private List<String> okHeadersToList(Headers headers){
    //     List<String> headersList = new ArrayList<>();
    //     Map<String, List<String>> headersMap = headers.toMultimap();
    //     Iterator<Map.Entry<String, List<String>>> iterator= headersMap.entrySet().iterator();
    //     while (iterator.hasNext()){
    //         Map.Entry<String, List<String>> entry = iterator.next();
    //         String key = entry.getKey();
    //         Iterator<String> values = entry.getValue().iterator();
    //         StringBuilder valueStringBuilder = new StringBuilder();
    //         while (values.hasNext()){
    //             String value = values.next();
    //             valueStringBuilder.append(value);
    //             if (values.hasNext()){ //当后面还有值的时候才添加;分割，如果是最后一个就不添加;了，会导致host路由错误
    //                 valueStringBuilder.append(";");
    //             }
    //         }
    //         headersList.add(String.format("%s: %s", key, valueStringBuilder));
    //     }
    //     return headersList;
    // }
}
