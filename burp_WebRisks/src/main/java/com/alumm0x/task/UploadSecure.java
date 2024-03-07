package com.alumm0x.task;

import burp.IHttpRequestResponse;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UploadSecure extends VulTaskImpl {

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse) {
        return new UploadSecure(requestResponse);
    }
    private UploadSecure(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、修改文件名类型
         * 2、修改请求体中content-type的类型，有些是根据这里去设置文件类型的
         * */
        //限定contentype的头部为文件上传的类型
        String contentYtpe = ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "Content-Type");
        if (contentYtpe.contains("multipart/form-data")){
            String fileName = "shell.php";
            //如果有body参数，需要多body参数进行测试
            String request_body_str = new String(BurpReqRespTools.getReqBody(requestResponse));
            if (request_body_str.length() > 0){
                //1.检查后缀名
                String regex = "filename=\"(.*?)\""; //分组获取文件名
                Pattern pattern = Pattern.compile(regex);
                Matcher matcher = pattern.matcher(request_body_str);
                if (matcher.find()){//没匹配到则不进行后续验证
                    String fileOrigin = matcher.group(1);
                    // 修改为别的域名
                    String req_body = request_body_str.replace(fileOrigin, fileName);
                    //新的请求包
                    okHttpRequester.send(
                            BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                            BurpReqRespTools.getMethod(requestResponse), 
                            BurpReqRespTools.getReqHeaders(requestResponse), 
                            BurpReqRespTools.getQuery(requestResponse), 
                            req_body, 
                            BurpReqRespTools.getContentType(requestResponse), 
                            new UploadSecureCallback(this));
                    //2.修改content-type
                    String regex1 = "Content-Type:\\s(.*?)\\s"; //分组获取文件名
                    Pattern pattern1 = Pattern.compile(regex1);
                    Matcher matcher1 = pattern1.matcher(request_body_str);
                    if (!matcher1.find()){//没匹配到则不进行后续验证
                        String ctOrigin = matcher1.group(1);
                        // 修改为别的ct,在上面修改后缀的基础下
                        String req_body1 = req_body.replace(ctOrigin, "application/x-httpd-php");
                        //新的请求包
                        okHttpRequester.send(
                            BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                            BurpReqRespTools.getMethod(requestResponse), 
                            BurpReqRespTools.getReqHeaders(requestResponse), 
                            BurpReqRespTools.getQuery(requestResponse), 
                            req_body1, 
                            BurpReqRespTools.getContentType(requestResponse), 
                            new UploadSecureCallback(this));
                    }
                }
            }
        }
    }

}

class UploadSecureCallback implements Callback {

    VulTaskImpl vulTask;

    public UploadSecureCallback(VulTaskImpl vulTask){
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
            UploadSecure.class.getSimpleName(),
            "onFailure", 
            "[UploadSecureCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        if (response.isSuccessful()){
            // 可能响应并没有回馈，所以这时响应是成功的也告警
            message = "Upload";
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            UploadSecure.class.getSimpleName(),
            message, 
            null);
    }
}