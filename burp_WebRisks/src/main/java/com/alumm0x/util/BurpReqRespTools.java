package com.alumm0x.util;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import okhttp3.*;
import okio.Buffer;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * 因为IHttpRequestResponse可以反复使用，解析获取到其中信息，不想OKHTTP的响应体只能获取一次
 * 所以这里就把所有IHttpRequestResponse的数据获取封装成函数，减少其他类的成员变量
 * 进一步优化运行时内存的消耗
 */
public class BurpReqRespTools {

    /**
     * 将OKhttp的请求及响应转换成Burp的对象
     * @param call OKhttp的请求对象
     * @param response OKhttp的响应对象
     * @param httpService burp的IHttpService，使用send功能时需要用到这个，所以需要设置到IHttpRequestResponse
     * @return IHttpRequestResponse
     */
    public static IHttpRequestResponse makeBurpReqRespFormOkhttp(Call call, Response response, IHttpRequestResponse requestResponse){
        IHttpRequestResponse newrequestResponse = new HttpRequestResponseFactory();;//根据响应构造burp的IHttpRequestResponse对象
        byte[] ok_reqInfo = new byte[0];
        byte[] ok_respInfo = new byte[0];
        if (call != null) {
            ok_reqInfo = okhttpReqToburpReq(call, requestResponse);
        }
        if (response != null) {
            ok_respInfo = okhttpRespToburpResp(call, response, requestResponse);
        }
        
        newrequestResponse.setRequest(ok_reqInfo);
        newrequestResponse.setResponse(ok_respInfo);
        newrequestResponse.setHttpService(BurpReqRespTools.getHttpService(requestResponse));
        return  newrequestResponse;
    }

    /**
     * 将okhttp的请求信息转换成burp的格式，以便展示
     * @param call OKhttp的请求对象
     * @param response OKhttp的响应对象
     * @return byte[]
     */
    public static byte[] okhttpReqToburpReq(Call call, IHttpRequestResponse requestResponse){
        RequestBody ok_requestBodyObj = call.request().body();
        String ok_method = call.request().method();
        String ok_url = call.request().url().url().getPath() + "?" + call.request().url().url().getQuery();
        String ok_protocol = BurpReqRespTools.getReqHeaderProtocol(requestResponse);//HTTP/1.1、HTTP/2
        Headers ok_reqHeaders = call.request().headers();
        String ok_reqBody = "";
        //获取requestBody
        Buffer buffer = new Buffer();
        try {//为空会报错，但是get请求体就是为空的
            Objects.requireNonNull(ok_requestBodyObj).writeTo(buffer);
            //编码设为UTF-8
            Charset charset = StandardCharsets.UTF_8; //默认UTF-8
            MediaType contentType = ok_requestBodyObj.contentType();
            if (contentType != null) {
                Charset charset0 = contentType.charset(StandardCharsets.UTF_8);
                if (charset0 != null){ //有些contentType是没带charset的
                    charset = charset0;
                }
            }
            //拿到requestBody
            ok_reqBody = buffer.readString(charset);
        } catch (Exception e) {
            //保持默认值空字符串即可
            BurpExtender.callbacks.printError("[okhttpReqToburpReq] ok_reqBody -> " + e.getMessage());
        }

        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(ok_method + " " + ok_url + " " + ok_protocol).append("\r\n");
        //stringBuilder.append(ok_reqHeaders); // Header默认将Cookie视为敏感数据，toString会给脱敏了，所以ui上看不到cookie，但实际请求不影响
        for (String header : //直接改用原headers进行构造burp的展示request,官方也有提供返回明文的：Headers.toMultimap().toString()，不过数据处理比较麻烦，还是用burp原生的吧
                okHeadersToList(ok_reqHeaders)) {
            stringBuilder.append(header).append("\r\n");
        }
        stringBuilder.append("\r\n");
        stringBuilder.append(ok_reqBody);

        return stringBuilder.toString().getBytes(StandardCharsets.UTF_8);

    }
    /**
     * 将okhttp的响应信息转换成burp的格式，以便展示
     * @param call OKhttp的请求对象
     * @param response OKhttp的响应对象
     * @return byte[]
     */
    public static byte[] okhttpRespToburpResp(Call call, Response response, IHttpRequestResponse requestResponse){
        int ok_code = response.code();
        String ok_message = response.message();
        Headers ok_respHeaders = response.headers();
        String ok_protocol = BurpReqRespTools.getRespHeaderProtocol(requestResponse);//HTTP/1.1必须要大写
        String ok_respBody = "";
        try {
            // okhttp响应正文乱码,因为没法处理压缩内容的解码
            // https://wenku.baidu.com/view/6d3d3afda68da0116c175f0e7cd184254b351b68.html
            // https://blog.csdn.net/xx326664162/article/details/81661861?utm_medium=distribute.pc_aggpage_search_result.none-task-blog-2~aggregatepage~first_rank_ecpm_v1~rank_v31_ecpm-3-81661861-null-null.pc_agg_new_rank&utm_term=okhttp%E5%93%8D%E5%BA%94%E5%AD%97%E7%AC%A6%E4%B8%B2%E4%B9%B1%E7%A0%81&spm=1000.2123.3001.4430
            ok_respBody = Objects.requireNonNull(response.body()).string(); //只能调用一次，即关闭response,所以最后调用
        } catch (IOException e) {
            BurpExtender.callbacks.printError("[okhttpRespToburpResp]response.body() -> " + e.getMessage());
        }
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(ok_protocol + " " + ok_code + " " + ok_message).append("\r\n");
        for (String header : //直接改用原headers进行构造burp的展示request,官方也有提供返回明文的：Headers.toMultimap().toString()，不过数据处理比较麻烦，还是用burp原生的吧
                okHeadersToList(ok_respHeaders)) {
            stringBuilder.append(header).append("\r\n");
        }
        stringBuilder.append("\r\n");
        stringBuilder.append(ok_respBody);

        return  stringBuilder.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 将Headers转换成List，使用toMultimap，解决敏感字段被okhttp脱敏的问题
     * 头部信息格式：name:value,匹配burp获取的头部信息格式
     * @param headers Okhttp的Headers对象
     * @return List<String>
     */
    public static List<String> okHeadersToList(Headers headers){
        List<String> headersList = new ArrayList<>();
        Map<String, List<String>> headersMap = headers.toMultimap();
        Iterator<Map.Entry<String, List<String>>> iterator= headersMap.entrySet().iterator();
        while (iterator.hasNext()){
            Map.Entry<String, List<String>> entry = iterator.next();
            String key = entry.getKey();
            Iterator<String> values = entry.getValue().iterator();
            StringBuilder valueStringBuilder = new StringBuilder();
            while (values.hasNext()){
                String value = values.next();
                valueStringBuilder.append(value);
                if (values.hasNext()){ //当后面还有值的时候才添加;分割，如果是最后一个就不添加;了，会导致host路由错误
                    valueStringBuilder.append(";");
                }
            }
            headersList.add(String.format("%s: %s", key, valueStringBuilder));
        }
        return headersList;
    }

    /**
     * 从burp的IHttpRequestResponse中获取请求头信息
     * @param requestResponse burp的IHttpRequestResponse
     * @return List<String>
     */
    public static List<String> getReqHeaders(IHttpRequestResponse requestResponse) {
        if (requestResponse != null) {
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestResponse);
            List<String> reqheaders = requestInfo.getHeaders();
            reqheaders.remove(0); // 删除状态行，不然下面splite取值会越界
            return reqheaders;
        }
        return null;
    }

    /**
     * 从burp的IHttpRequestResponse中获取请求头信息,返回健值对的格式
     * @param requestResponse burp的IHttpRequestResponse
     * @return Map<String, String>
     */
    public static Map<String, Object> getReqHeadersToMap(IHttpRequestResponse requestResponse) {
        Map<String, Object> headers = new HashMap<>();
        if (requestResponse != null) {
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestResponse);
            List<String> reqheaders = requestInfo.getHeaders();
            reqheaders.remove(0); // 删除状态行，不然下面splite取值会越界
            int index = 0; // 用于重复的头部的添加
            for (String header : reqheaders) {
                String[] kv = header.split(":");
                if (headers.keySet().contains(kv[0])) {
                    // 重复的则key后面追加xx_index
                    headers.put(kv[0].trim() + "_" + ++index, kv[1].trim());
                } else {
                    headers.put(kv[0].trim(), kv[1].trim());
                } 
            }
        }
        return headers;
    }


    /**
     * 从burp的IHttpRequestResponse中获取请求体信息
     * @param requestResponse burp的IHttpRequestResponse
     * @return byte[]
     */
    public static byte[] getReqBody(IHttpRequestResponse requestResponse) {
        if (requestResponse != null) {
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestResponse);
            return Arrays.copyOfRange(requestResponse.getRequest(), requestInfo.getBodyOffset(), requestResponse.getRequest().length);
        }
        return new byte[]{};
    }

    /**
     * 从burp的IHttpRequestResponse中获取响应头信息
     * @param requestResponse burp的IHttpRequestResponse
     * @return List<String>
     */
    public static List<String> getRespHeaders(IHttpRequestResponse requestResponse) {
        if (requestResponse != null) {
            IResponseInfo responseInfo = BurpExtender.helpers.analyzeResponse(requestResponse.getResponse());
            List<String> respHeaders = responseInfo.getHeaders();
            respHeaders.remove(0); // 删除状态行，不然下面splite取值会越界
            return respHeaders;
        }
        return null;
    }

    /**
     * 从burp的IHttpRequestResponse中获取响应头头信息,返回健值对的格式
     * @param requestResponse burp的IHttpRequestResponse
     * @return Map<String, String>
     */
    public static Map<String, String> getRespHeadersToMap(IHttpRequestResponse requestResponse) {
        Map<String, String> headers = new HashMap<>();
        if (requestResponse != null) {
            IResponseInfo responseInfo = BurpExtender.helpers.analyzeResponse(requestResponse.getResponse());
            List<String> reqheaders = responseInfo.getHeaders();
            reqheaders.remove(0); // 删除状态行，不然下面splite取值会越界
            int index = 0; // 用于重复的头部的添加
            for (String header : reqheaders) {
                String[] kv = header.split(":");
                if (headers.keySet().contains(kv[0])) {
                    // 重复的则key后面追加xx_index
                    headers.put(kv[0].trim() + "_" + ++index, kv[1].trim());
                } else {
                    headers.put(kv[0].trim(), kv[1].trim());
                } 
            }
        }
        return headers;
    }

    /**
     * 从burp的IHttpRequestResponse中获取响应体信息
     * @param requestResponse  burp的IHttpRequestResponse
     * @return byte[]
     */
    public static byte[] getRespBody(IHttpRequestResponse requestResponse) {
        if (requestResponse != null) {
            IResponseInfo responseInfo = BurpExtender.helpers.analyzeResponse(requestResponse.getResponse());
            return Arrays.copyOfRange(requestResponse.getResponse(), responseInfo.getBodyOffset(), requestResponse.getResponse().length);
        }
        return new byte[]{};
    }

    /**
     * 获取HttpService对象
     * @param requestResponse  burp的IHttpRequestResponse
     * @return byte[]
     */
    public static IHttpService getHttpService(IHttpRequestResponse requestResponse){
        if (requestResponse != null) {
            return requestResponse.getHttpService();
        }
        return null;
    }

    /**
     * 获取请求的Host
     * @param requestResponse
     * @return Host
     */
    public static String getHost(IHttpRequestResponse requestResponse){
        if (requestResponse != null) {
            return requestResponse.getHttpService().getHost();
        }
        return null;
    }

    /**
     * 获取请求的端口
     * @param requestResponse
     * @return Port
     */
    public static int getPort(IHttpRequestResponse requestResponse){
        if (requestResponse != null) {
            return requestResponse.getHttpService().getPort();
        }
        return 0;
    }

    /**
     * 获取请求使用的协议，如http、https
     * @param requestResponse
     * @return Protocol
     */
    public static String getProtocol(IHttpRequestResponse requestResponse){
        if (requestResponse != null) {
            return requestResponse.getHttpService().getProtocol();
        }
        return null;
    }

    /**
     * 从burp的IHttpRequestResponse中获取请求头信息的首行的protocol，eg：GET /xxx HTTP/1.1 获取得到 HTTP/1.1
     * 注意: 由于okhttp的http2包里面写的H2，但这个在burp中解析不到，因为burp中是这么表示HTTP/2
     * @param requestResponse burp的IHttpRequestResponse
     * @return List<String>
     */
    public static String getReqHeaderProtocol(IHttpRequestResponse requestResponse) {
        if (requestResponse != null) {
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestResponse);
            List<String> reqheaders = requestInfo.getHeaders();
            String[] ls = reqheaders.get(0).split("\\s+");
            if (ls.length < 3) {
                return "HTTP/1.1";
            }
            // 注意: 由于okhttp的http2包里面写的H2，但这个在burp中解析不到，因为burp中是这么表示HTTP/2
            if (ls[2].equalsIgnoreCase("h2")) {
                return "HTTP/2";
            }
            return ls[2];
        }
        return null;
    }

    /**
     * 从burp的IHttpRequestResponse中获取响应头头信息的首行的protocol，eg：HTTP/1.1 200 OK 获取得到 HTTP/1.1
     * 注意: 由于okhttp的http2包里面写的H2，但这个在burp中解析不到，因为burp中是这么表示HTTP/2
     * @param requestResponse burp的IHttpRequestResponse
     * @return List<String>
     */
    public static String getRespHeaderProtocol(IHttpRequestResponse requestResponse) {
        if (requestResponse != null) {
            IResponseInfo responseInfo = BurpExtender.helpers.analyzeResponse(requestResponse.getResponse());
            List<String> respheaders = responseInfo.getHeaders();
            String[] ls = respheaders.get(0).split("\\s+");
            if (ls.length > 1) { // 兼容h2版本，会有eg：H2 405
                // 注意: 由于okhttp的http2包里面写的H2，但这个在burp中解析不到，因为burp中是这么表示HTTP/2
                if (ls[0].equalsIgnoreCase("h2")) {
                    return "HTTP/2";
                }
                return ls[0];
            }
        }
        return null;
    }

    /**
     * 获取请求method
     * @param requestResponse  burp的IHttpRequestResponse
     * @return String
     */
    public static String getMethod(IHttpRequestResponse requestResponse){
        if (requestResponse != null) {
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestResponse);
            return requestInfo.getMethod();
        }
        return "";
    }

    /**
     * 获取请求的url，带查询参数的
     * @param requestResponse  burp的IHttpRequestResponse
     * @return String
     */
    public static String getUrl(IHttpRequestResponse requestResponse){
        if (requestResponse != null) {
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestResponse);
            return requestInfo.getUrl().toString().replace(":443/", "/").replace(":80/", "/");
        }
        return "";
    }

    /**
     * 获取请求的url，不带urlpath，如https://xxx.com/sdfasd -> https://xxx.com/
     * @param requestResponse  burp的IHttpRequestResponse
     * @return String
     */
    public static String getRootUrl(IHttpRequestResponse requestResponse){
        if (requestResponse != null) {
            StringBuffer url = new StringBuffer();
            url.append(requestResponse.getHttpService().getProtocol()).append("://").append(requestResponse.getHttpService().getHost()).append("/");
            return url.toString().replace(":443/", "/").replace(":80/", "/");
        }
        return "";
    }

    /**
     * 获取请求的url，不带查询参数的
     * @param requestResponse  burp的IHttpRequestResponse
     * @return String
     */
    public static String getUrlWithOutQuery(IHttpRequestResponse requestResponse){
        if (requestResponse != null) {
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestResponse);
            return requestInfo.getUrl().toString().replace(":443/", "/").replace(":80/", "/").split("\\?", 2)[0];
        }
        return "";
    }

    /**
     * 获取请求的url的path
     * @param requestResponse  burp的IHttpRequestResponse
     * @return String
     */
    public static String getUrlPath(IHttpRequestResponse requestResponse){
        if (requestResponse != null) {
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestResponse);
            return requestInfo.getUrl().getPath();
        }
        return "";
    }

    /**
     * 获取请求的查询参数
     * @param requestResponse  burp的IHttpRequestResponse
     * @return String
     */
    public static String getQuery(IHttpRequestResponse requestResponse){
        if (requestResponse != null) {
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestResponse);
            return requestInfo.getUrl().getQuery();
        }
        return null;
    }

    /**
     * 获取请求的查询参数
     * @param requestResponse  burp的IHttpRequestResponse
     * @return Map<String, String>
     */
    public static Map<String, Object> getQueryMap(IHttpRequestResponse requestResponse){
        Map<String, Object> queryParams = new HashMap<>();
        if (requestResponse != null) {
            String querystring = getQuery(requestResponse);
            if (querystring != null) { // getQuery会返回null
                String[] kv = querystring.split("&");
                for (String query : kv) {
                    String[] keyvalue = query.split("=", 2);
                    if (keyvalue.length == 2) {
                        queryParams.put(keyvalue[0].trim(), keyvalue[1].trim());
                    }
                }
            }
        }
        return queryParams;
    }

    /**
     * 获取请求的content-type
     * @param requestResponse  burp的IHttpRequestResponse
     * @return String
     */
    public static String getContentType(IHttpRequestResponse requestResponse){
        if (requestResponse != null) {
            IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(requestResponse);

            // 获取content-type
            switch (requestInfo.getContentType()) {
                case 0:
                case 1:
                    // byte CONTENT_TYPE_URL_ENCODED = 1;
                    // byte CONTENT_TYPE_NONE = 0;
                    return "application/x-www-form-urlencoded";
                case 2:
                    //byte CONTENT_TYPE_MULTIPART = 2;
                    return "multipart/form-data";
                case 3:
                    //byte CONTENT_TYPE_XML = 3;
                    return "application/xml";
                case 4:
                    //byte CONTENT_TYPE_JSON = 4;byte CONTENT_TYPE_AMF = 5;
                    return "application/json";
                case 5:
                    //byte CONTENT_TYPE_AMF = 5;
                    return "application/x-amf";
                default:
                    //byte CONTENT_TYPE_UNKNOWN = -1;
                    return "UNKNOWN";
            }
        }
        return "UNKNOWN";
    }
    /**
     * 获取burp的IRequestInfo
     * @param requestResponse  burp的IHttpRequestResponse
     * @return IRequestInfo
     */
    public static IRequestInfo getRequestInfo(IHttpRequestResponse requestResponse){
        return BurpExtender.helpers.analyzeRequest(requestResponse);
    }

    /**
     * 获取burp的IResponseInfo
     * @param requestResponse  burp的IHttpRequestResponse
     * @return IResponseInfo
     */
    public static IResponseInfo getRespuestInfo(IHttpRequestResponse requestResponse) {
        return BurpExtender.helpers.analyzeResponse(requestResponse.getResponse());
    }

    /**
     * 获取burp的IResponseInfo
     * @param requestResponse  burp的IHttpRequestResponse
     * @return short
     */
    public static short getStatus(IHttpRequestResponse requestResponse) {
        if (requestResponse != null) {
            return BurpExtender.helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode();
        }
        return -1;
    }
}
