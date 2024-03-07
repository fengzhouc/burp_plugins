package com.alumm0x.util;

import java.util.*;

import org.json.JSONArray;
import org.json.JSONObject;

import burp.BurpExtender;

public class JsonTools {
    //存储json参数名的，用于bean参数注入
    //TODO 注入的参数值，为了保证业务处理，最好是根据原数据类型去生成，怎么搞？？
    // 改为map，保存原value，在原值基础上进行修改？？
    // 数据共三种情况：布尔/数字/字符串
    public List<String> paramKeys;
    // 保存篡改的json串
    public final StringBuilder stringBuilder;

    public JsonTools(){
        this.stringBuilder = new StringBuilder();
        this.paramKeys = new ArrayList<>();
    }

    //保存json的key参数名
    private void addParam(String param){
        // 不存在才添加
        if (!this.paramKeys.contains(param)){
            this.paramKeys.add(param);
        }
    }

    //修改后还原json字符串
    private void write(String hash, boolean add){
        if (!add) {
            stringBuilder.append(hash);
        }else {
            stringBuilder.append(hash).append(",");
        }
    }
    /**
     * 遍历json对象，每个值中插入标记
     * @niject 注入的参数
     * */
    //初始是jsonObject
    @SuppressWarnings("unchecked")
    public void jsonObjInject(Map<String, Object> jsonMap, String inject) {
        write("{", false);
        Iterator<Map.Entry<String, Object>> iterator = jsonMap.entrySet().iterator();
        while (iterator.hasNext()){
            Map.Entry<String, Object> entry = iterator.next();
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof HashMap){ //json对象
//                System.out.println("Key = " + key + " //JsonObject");
                write(String.format("\"%s\":{", key),false);
                Iterator<Map.Entry<String, Object>> iteratorValue = ((Map<String, Object>)value).entrySet().iterator();
                while (iteratorValue.hasNext()){
                    Map.Entry<String, Object> entryValue = iteratorValue.next();
                    if (entryValue instanceof HashMap) { //值也可能是对象
                        jsonObjInject((Map<String, Object>) entryValue, inject);
                    }else {//基础类型数据就是最里层的结果了 key:value
//                        System.out.println("--Key = " + entryValue.getKey() + ", Value = " + entryValue.getValue() + ", type: " + entryValue.getValue().getClass());
                        write(String.format("\"%s\":\"%s\"", entryValue.getKey(), entryValue.getValue() + inject), iteratorValue.hasNext());
                    }
                }
                write("}", iterator.hasNext());
            }else if (value instanceof ArrayList){ //json数组
                write(String.format("\"%s\":[", key), false);
                Iterator<Object> iteratorArray = ((ArrayList<Object>)value).iterator();
//                System.out.println("Key = " + key + " //JsonArray");
                while (iteratorArray.hasNext()){
                    Object obj = iteratorArray.next();
                    if (obj instanceof HashMap) { //有可能是对象数组
                        jsonObjInject((Map<String, Object>) obj, inject);
                    }else { //要么就是基础类型数据了,就是最终结果了
//                        System.out.println("--Value = " + obj + ", type: " + obj.getClass());
                        write(String.format("\"%s\"", obj + inject), iteratorArray.hasNext());
                    }
                }
                write("]", iterator.hasNext());
            }else {//基础类型数据就是最里层的结果了 key:value
                write(String.format("\"%s\":\"%s\"",key, value + inject), iterator.hasNext());
//                System.out.println(String.format("Key = %s  Value = %s, type: %s",key, value, value.getClass()));
            }
        }
        write("}", false);
    }

    //初始是jsonArray的
    /**
     * 遍历json数组，每个值中插入标记
     * @niject 注入的参数
     * */
    @SuppressWarnings("unchecked")
    public void jsonArrInject(List<Object> jsonList, String inject) {
        write("[", false);
        Iterator<Object> iterator = jsonList.iterator();
        while (iterator.hasNext()){
            Object value = iterator.next();
//            System.out.println(value + " ,type: " + value.getClass());
            if (value instanceof HashMap){ //json对象数组
                jsonObjInject((Map<String, Object>)value, inject);
            }else {//基础类型数据就是最里层的结果了 value，value1，value2
                write(String.format("\"%s\"", value + inject), iterator.hasNext());
            }
        }
        write("]", false);
    }

    /**
     * 解析json字符串里的对象，放回 Map
     * @param object
     * @return Map
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public static Map jsonObjectToMap(Object object) {
        String source = object.toString().substring(1,object.toString().length()-1).replace("=",":");
        JSONObject jsonObject = new JSONObject(source);
        Map objectMap = jsonObject.toMap();
        objectMap.forEach((key,value) -> System.out.println(key + "\t" + value));
        return objectMap;
    }

    // 解析json，然后添加注入字符
    // https://blog.csdn.net/zitong_ccnu/article/details/47375379
    public static String createJsonBody(String body, String injectStr){
        try {
            if (body.startsWith("{")){
                JSONObject jsonObject = new JSONObject(body);
                Map<String, Object> jsonMap = jsonObject.toMap();
                JsonTools jsonTools = new JsonTools();
                jsonTools.jsonObjInject(jsonMap, injectStr);
                return jsonTools.stringBuilder.toString();
            }else if (body.startsWith("[")){
                JSONArray jsonArray = new JSONArray(body);
                List<Object> jsonList = jsonArray.toList();
                JsonTools jsonTools = new JsonTools();
                jsonTools.jsonArrInject(jsonList, injectStr);
                return jsonTools.stringBuilder.toString();
            }
        } catch (Exception e) {
            BurpExtender.callbacks.printError("createJsonBody:\n" + e +
                    "\nerrorData:\n" + body);
        }
        //非json数据直接原文返回
        return body;
    }

    public static String createFormBody(String body, String injectStr){
        String[] qs = body.split("&");
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0;i<qs.length -1;i++){
            stringBuilder.append(qs[i]).append(injectStr).append("&");
        }
        stringBuilder.append(qs[qs.length-1]); //最后的参数不添加&
        return stringBuilder.toString();
    }
}
