package com.alumm0x.task;

import burp.IHttpRequestResponse;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONObject;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;

import java.io.IOException;
import java.util.*;

public class BeanParamInject extends VulTaskImpl {

    private final StringBuilder stringBuilder;

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new BeanParamInject(requestResponse);
    }

    private BeanParamInject(IHttpRequestResponse requestResponse) {
        super(requestResponse);
        this.stringBuilder = new StringBuilder();
    }

    @Override
    public void run() {
        /**
         * 检测逻辑：当前只检测响应中会打印完整bean信息的情况
         * 1、解析响应获取参数名
         * 2、然后再请求中添加额外的参数进行重放
         * */
        // 1.分析请求及响应的字段信息
        // 2.找到有公共参数的地方，如果没有公共参数，则不继续
        // 3.然后提取出请求参数没有的，提取key:value
        // 4.在请求中添加参数，参数值根据原值进行微调
        // 5.重放后检查响应中的值是否也被修改
        // 疑问：按我理解框架会自动将json对象（不一定是json，还有form表单的也可以）转换为bean，一般bean就是getter/setter方法，如果不存在的字段会不会报错？
        // 实验结果：缺少或者冗余参数都不会报错，正常初始化

        //仅检测json数据的，目前使用json的多，form的很少了
        if (BurpReqRespTools.getContentType(requestResponse).contains("application/json")){
            String flag = "beanInject";
            //必须要有请求参数,且是json对象
            if (BurpReqRespTools.getReqBody(requestResponse).length > 0 && new String(BurpReqRespTools.getReqBody(requestResponse)).startsWith("{"))
            {
                //如果响应体信息比请求体信息少，则可能没有反馈bean信息，这样就无法检测了，pass
                String respbody = new String(BurpReqRespTools.getRespBody(requestResponse));
                if (BurpReqRespTools.getRespBody(requestResponse).length > BurpReqRespTools.getReqBody(requestResponse).length){
                    JSONObject reqJsonObject = new JSONObject(BurpReqRespTools.getReqBody(requestResponse));
                    Map<String, Object> reqJsonMap = reqJsonObject.toMap();
                    if (respbody.startsWith("{")) {
                        JSONObject respJsonObject = new JSONObject(respbody);
                        Map<String, Object> respJsonMap = respJsonObject.toMap();
                        //1.分析并得出公共参数及缺少的参数
                        // -简单json对象,循环json对象，查看响应中是否有次key
                        // -复杂json对象,这里相对上面的需要注意的是需要定位是在哪个json对象中插入数据
                        Map<String, Object> beanJsonMap = getBeanJsonObjMap(reqJsonMap, respJsonMap);
                        //2.将缺少的参数注入到请求参数中并修改值，重放请求，循环所有缺少的参数
                        assert beanJsonMap != null;
                        jsonObjInject(beanJsonMap, reqJsonMap, flag);
                    }else if (respbody.startsWith("[")){
                        JSONArray respJsonArray = new JSONArray(respbody);
                        List<Object> respJsonMap = respJsonArray.toList();
                        //1.分析并得出公共参数及缺少的参数
                        // -简单json对象,循环json对象，查看响应中是否有次key
                        // -复杂json对象,这里相对上面的需要注意的是需要定位是在哪个json对象中插入数据
                        Map<String, Object> beanJsonMap = getBeanJsonObjMap(reqJsonMap, respJsonMap);
                        //2.将缺少的参数注入到请求参数中并修改值，重放请求，循环所有缺少的参数
                        assert beanJsonMap != null;
                        jsonObjInject(beanJsonMap, reqJsonMap, flag);
                    }
                    String new_body = stringBuilder.toString();
                    //3.查看响应中是否有篡改的值

                    //没有找到bean对象则不进行测试
                    if (!"".equalsIgnoreCase(new_body)){
                        //新的请求包
                        okHttpRequester.send(
                            BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                            BurpReqRespTools.getMethod(requestResponse), 
                            BurpReqRespTools.getReqHeaders(requestResponse), 
                            BurpReqRespTools.getQuery(requestResponse), 
                            new_body, 
                            BurpReqRespTools.getContentType(requestResponse), 
                            new BeanParamInjectCallback(this));
                    }
                }
            }
        }
    }
    //获取bean的jsonMap
    //如果响应中某个jsonObj包含所有请求中的jsonObj的key，则返回此jsonObj的map对象
    //只要当前json串中某个jsonObj满足要求即返回其map对象
    @SuppressWarnings("unchecked")
    private static Map<String, Object> getBeanJsonObjMap(Map<String, Object> reqJsonMap, Map<String, Object> respJsonMap){
        Iterator<Map.Entry<String, Object>> iterator = respJsonMap.entrySet().iterator();
        Map<String, Object> result = null;
        int col = reqJsonMap.size();
        while (iterator.hasNext()){
            Map.Entry<String, Object> entry = iterator.next();
            String key = entry.getKey();
            if (reqJsonMap.containsKey(key)){ //当前jsonObjt是否包含请求中的key，包含则计数+1
                col -= 1;
                continue; //如果key包含了，那就不关心其值类型了，检查下一个
            }
            Object value = entry.getValue();
            if (value instanceof HashMap){ //json对象
                result = getBeanJsonObjMap(reqJsonMap, (Map<String, Object>) value);
                System.out.println("0-" + result);
            }else if (value instanceof ArrayList){ //json数组
                Iterator<Object> iteratorArray = ((ArrayList<Object>)value).iterator();
                while (iteratorArray.hasNext()){
                    Object obj = iteratorArray.next();
                    if (obj instanceof HashMap) { //有可能是对象数组
                        result = getBeanJsonObjMap(reqJsonMap, (Map<String, Object>) obj);
                        System.out.println("1-" + result);
                    }
                }
            }
        }
        // 只要包含所有请求中的jsonObj的key则返回
        if (col == 0){
            result = respJsonMap;
        }else if (result != null){
            return result;
        }
        return result;
    }

    //如果响应是json数组的话，则使用这个进行便利，获取bean
    private static Map<String, Object> getBeanJsonObjMap(Map<String, Object> reqJsonMap, List<Object> respJsonList){
        Iterator<Object> iteratorList = respJsonList.iterator();
        while(iteratorList.hasNext()) {
            Object valueList = iteratorList.next();
            if (valueList instanceof HashMap) {
                @SuppressWarnings("unchecked")
                Map<String, Object> result = getBeanJsonObjMap(reqJsonMap, (Map<String, Object>)valueList);
                if (result != null){
                    return result;
                }
            }
        }
        return null;
    }

    private void write(String hash, boolean add){
        if (!add) {
            stringBuilder.append(hash);
        }else {
            stringBuilder.append(hash).append(",");
        }
    }
    // 参数注入的方法
    // 只会将reqJsonObj中没有key的值进行修改，设置为flag
    @SuppressWarnings("unchecked")
    private void jsonObjInject(Map<String, Object> jsonMap,Map<String, Object> reqJsonMap, String inject) {
        write("{", false);
        Iterator<Map.Entry<String, Object>> iterator = jsonMap.entrySet().iterator();
        while (iterator.hasNext()){
            Map.Entry<String, Object> entry = iterator.next();
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof HashMap){ //json对象
                write(String.format("\"%s\":{", key),false);
                Iterator<Map.Entry<String, Object>> iteratorValue = ((Map<String, Object>)value).entrySet().iterator();
                while (iteratorValue.hasNext()){
                    Map.Entry<String, Object> entryValue = iteratorValue.next();
                    if (entryValue instanceof HashMap) { //值也可能是对象
                        jsonObjInject((Map<String, Object>) entryValue, reqJsonMap, inject);
                    }else {//基础类型数据就是最里层的结果了 key:value
                        if (reqJsonMap.containsKey(entryValue.getKey())) {
                            write(String.format("\"%s\":\"%s\"", entryValue.getKey(), entryValue.getValue()), iteratorValue.hasNext());
                        }else {
                            write(String.format("\"%s\":\"%s\"", entryValue.getKey(), inject), iteratorValue.hasNext());
                        }
                    }
                }
                write("}", iterator.hasNext());
            }else if (value instanceof ArrayList){ //json数组
                write(String.format("\"%s\":[", key), false);
                Iterator<Object> iteratorArray = ((ArrayList<Object>)value).iterator();
                while (iteratorArray.hasNext()){
                    Object obj = iteratorArray.next();
                    if (obj instanceof HashMap) { //有可能是对象数组
                        jsonObjInject((Map<String, Object>) obj, reqJsonMap, inject);
                    }else { //要么就是基础类型数据了,就是最终结果了
                        write(String.format("\"%s\"", obj), iteratorArray.hasNext());
                    }
                }
                write("]", iterator.hasNext());
            }else {//基础类型数据就是最里层的结果了 key:value
                if (reqJsonMap.containsKey(key)) {
                    write(String.format("\"%s\":\"%s\"", key, value), iterator.hasNext());
                }else {
                    write(String.format("\"%s\":\"%s\"", key, inject), iterator.hasNext());
                }
            }
        }
        write("}", false);
    }
}

class BeanParamInjectCallback implements Callback {

    VulTaskImpl vulTask;

    public BeanParamInjectCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        // 记录日志
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, null, vulTask.requestResponse);
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            BeanParamInject.class.getSimpleName(),
             "onFailure", 
             "[BeanParamInjectCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        //如果响应成功，则检查值是否被修改
        if (response.isSuccessful()) {
            // 记录日志
            // 检查响应中是否存在flag
            if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains("beanInject")) {
                message = "BeanParamInject";
            }
        }else { //啥情况会不成功，做了些数据校验的时候，比如这个字段只允许String，我改成int，可能就会报错，那报错就可能就是用了bean
            message = "BeanParamInject-error";
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            BeanParamInject.class.getSimpleName(),
            message, 
            null);
    }
}