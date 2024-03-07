package com.alumm0x.task.collect;

import burp.IHttpRequestResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.SourceLoader;

public class SensitiveMessage extends VulTaskImpl {

    String payloads = "";

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new SensitiveMessage(requestResponse);
    }
    private SensitiveMessage(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 检测响应匹配正则
         * */

        // 后缀检查，静态资源不做测试
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), new ArrayList<>())){
            //如果有响应才检测
            String resp_body_str = new String(BurpReqRespTools.getRespBody(requestResponse));
            if (resp_body_str.length() > 0){
                //先检测是否存在url地址的参数，正则匹配
                String UIDRegex = "['\"&<;\\s/,][1-9]\\d{5}(18|19|([23]\\d))\\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\\d{3}[0-9Xx]['\"&<;\\s/,]"; //身份证的正则
                String phoneRegex = "['\"&<;\\s/,]+?1(3\\d|4[5-9]|5[0-35-9]|6[567]|7[0-8]|8\\d|9[0-35-9])\\d{8}['\"&<;\\s/,]+?"; //手机号的正则
                String emailRegex = "\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*"; //邮箱的正则
                Pattern patternUID = Pattern.compile(UIDRegex);
                Pattern patternPhone = Pattern.compile(phoneRegex);
                Pattern patternEmail = Pattern.compile(emailRegex);
                Matcher matcherUid = patternUID.matcher(resp_body_str);
                Matcher matcherPhone = patternPhone.matcher(resp_body_str);
                Matcher matcherEmail = patternEmail.matcher(resp_body_str);
                
                String message = "SensitiveMessage:";
                List<String> types = new ArrayList<>();
                types.add("SensitiveMessage:");
                if (matcherUid.find()){
                    types.add("UID");
                    payloads += "\n" + matcherUid.group();
                    while (matcherUid.find()){ //每次调用后会往后移
                        payloads += "\n" + matcherUid.group();
                    }
                }
                if (matcherPhone.find()){
                    types.add("Phone");
                    payloads += "\n" + matcherPhone.group();
                    while (matcherPhone.find()){ //每次调用后会往后移
                        payloads += "\n" + matcherPhone.group();
                    }
                }
                if (matcherEmail.find()){
                    types.add("Email");
                    payloads += "\n" + matcherEmail.group();
                    while (matcherEmail.find()){ //每次调用后会往后移
                        payloads += "\n" + matcherEmail.group();
                    }
                }
                if (!message.equalsIgnoreCase("SensitiveMessage:")) {
                    //不需要发包,上面正则匹配到则存在问题
                    MainPanel.logAdd(
                        requestResponse, 
                        BurpReqRespTools.getHost(requestResponse), 
                        BurpReqRespTools.getUrlPath(requestResponse),
                        BurpReqRespTools.getMethod(requestResponse), 
                        BurpReqRespTools.getStatus(requestResponse), 
                        SensitiveMessage.class.getSimpleName(),
                        String.join(",", types), 
                        String.join("\n", SourceLoader.loadSources("/payloads/SensitiveMessageRegex.bbm")));
                }
            }
        }
    }

}
