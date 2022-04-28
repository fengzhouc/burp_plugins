package burp.task;

import burp.*;
import burp.impl.VulResult;
import burp.impl.VulTaskImpl;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SqlInject extends VulTaskImpl {

    public SqlInject(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<BurpExtender.LogEntry> log, IHttpRequestResponse messageInfo) {
        super(helpers, callbacks, log, messageInfo);
    }

    @Override
    public VulResult run() {
        /**
         * 检测逻辑
         * 1、所有参数都添加特殊字符
         * 2、然后检查响应是否不同或者存在关键字
         * */

        String injectStr = "'\"\\\"";

        // 后缀检查，静态资源不做测试
        if (isStaticSource(path)){
            return null;
        }

        //反射型只测查询参数
        String query = request_header_list.get(0);
        if (query.contains("?"))
        {
            String queryParam = query.split("\\?")[1];
            List<String> new_headers = request_header_list;
            String header_first = "";
            header_first = query.replace(queryParam, createForm(queryParam, injectStr));
            //替换请求包中的url
            new_headers.remove(0);
            new_headers.add(0, header_first);

            //新的请求包
            IHttpRequestResponse messageInfo1 = BurpExtender.requester.send(this.iHttpService, new_headers, request_body_byte);

            //以下进行判断
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            String resp = new String(messageInfo1.getResponse());
            String resp1_body = resp.substring(analyzeResponse1.getBodyOffset());
            status = analyzeResponse1.getStatusCode();

            // 检查响应中是否存在flag
            if (resp1_body.contains("SQL")) {
                result = logAdd(messageInfo1, host, path, method, status, "SqlInject", payloads);
            }
        }
        //如果有body参数，需要多body参数进行测试
        if (request_body_str.length() > 0){
            String contentype = "";
            for (String header :
                    request_header_list) {
                if (header.contains("json")){
                    contentype = "json";
                }else if (header.contains("form")){
                    contentype = "form";
                }
            }
            String req_body = "";
            switch (contentype){
                case "json":
                    req_body = createJson(request_body_str, injectStr);
                    break;
                case "form":
                    req_body = createForm(request_body_str, injectStr);
                    break;
            }
            //新的请求包
            IHttpRequestResponse messageInfo1 = BurpExtender.requester.send(this.iHttpService, request_header_list, req_body.getBytes());
            //以下进行判断
            IResponseInfo analyzeResponse1 = this.helpers.analyzeResponse(messageInfo1.getResponse());
            String resp = new String(messageInfo1.getResponse());
            String resp1_body = resp.substring(this.analyzeResponse.getBodyOffset());
            status = analyzeResponse1.getStatusCode();

            // 检查响应中是否存在flag
            // TODO 关键字是否全
            if (resp1_body.contains("SQL")) {
                result = logAdd(messageInfo1, host, path, method, status, "SqlInject", payloads);
            }
        }

        return result;
    }
    // TODO 解析json，然后添加注入字符
    // https://blog.csdn.net/zitong_ccnu/article/details/47375379
    private String createJson(String body, String injectStr){
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
    private String createForm(String body, String injectStr){
        String[] qs = body.split("&");
        StringBuilder stringBuilder = new StringBuilder();
        for (String param : qs){
            stringBuilder.append(param).append(injectStr).append("&");
        }
        return stringBuilder.toString();
    }
}
