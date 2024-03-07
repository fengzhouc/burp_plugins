package com.alumm0x.task;

import burp.IHttpRequestResponse;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonMess;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmsEmailBoom extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new SmsEmailBoom(requestResponse);
    }
    private SmsEmailBoom(IHttpRequestResponse requestResponse) {
        super(requestResponse);
        CommonMess.SmsEmailBoomCount = 0; //初始化为0
    }

    @Override
    public void run() {
        /**
         * 邮箱\短信轰炸
         * */
        List<String> add = new ArrayList<String>();
        add.add(".js");
        // 后缀检查，静态资源不做测试
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            //如果请求参数中有邮箱，尝试下重放
            String request_body_str = new String(BurpReqRespTools.getReqBody(requestResponse));
            String query = BurpReqRespTools.getQuery(requestResponse);
            if (request_body_str.length() > 0 || query.length() > 0){
                //先检测是否存在url地址的参数，正则匹配
                String phoneRegex = "['\"&>;\\s/,=]+?1(3\\d|4[5-9]|5[0-35-9]|6[567]|7[0-8]|8\\d|9[0-35-9])\\d{8}['\"&<;\\s/,]+?"; //手机号的正则
                String emailRegex = "\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*"; //邮箱的正则
                Pattern patternPhone = Pattern.compile(phoneRegex);
                Pattern patternEmail = Pattern.compile(emailRegex);
                Matcher matcherPhone_body = patternPhone.matcher(request_body_str + "&"); // 为啥加&，为了区分边界，防止最后一个参数没法识别结束，主要是应付form表单
                Matcher matcherPhone_query = patternPhone.matcher(query + "&");
                Matcher matcherEmail_body = patternEmail.matcher(request_body_str + "&");
                Matcher matcherEmail_query = patternEmail.matcher(query + "&");
                if (matcherEmail_body.find() || matcherEmail_query.find()
                        || matcherPhone_body.find() || matcherPhone_query.find()){
                    for (int i = 0 ; i < 10 ; i++) { //重放10次
                        //新的请求包
                        okHttpRequester.send(
                            BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                            BurpReqRespTools.getMethod(requestResponse), 
                            BurpReqRespTools.getReqHeaders(requestResponse), 
                            BurpReqRespTools.getQuery(requestResponse), 
                            new String(BurpReqRespTools.getReqBody(requestResponse)), 
                            BurpReqRespTools.getContentType(requestResponse), 
                            new SmsEmailBoomCallback(this));
                    }
                }
            }
        }
    }
}

class SmsEmailBoomCallback implements Callback {

    VulTaskImpl vulTask;

    public SmsEmailBoomCallback(VulTaskImpl vulTask){
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
            SmsEmailBoom.class.getSimpleName(),
            "onFailure", 
            "[SmsEmailBoomCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (response.isSuccessful()){
            //如果状态码相同则可能存在问题
            if (BurpReqRespTools.getStatus(requestResponse) == BurpReqRespTools.getStatus(vulTask.requestResponse)
                && Arrays.equals(BurpReqRespTools.getRespBody(requestResponse),BurpReqRespTools.getRespBody(vulTask.requestResponse))) {
                CommonMess.SmsEmailBoomCount += 1; //判断存在问题则次数+1
                if (CommonMess.SmsEmailBoomCount == 10) { //重放10次都判断有问题，则极大可能存在轰炸风险
                    message = "SmsEmailBoom?? check device has got the sms.";
                }
            }
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            SmsEmailBoom.class.getSimpleName(),
            message, 
            null);
    }
}