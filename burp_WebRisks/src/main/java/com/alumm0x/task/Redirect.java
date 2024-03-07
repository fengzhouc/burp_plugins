package com.alumm0x.task;

import burp.*;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.SourceLoader;
import com.alumm0x.util.ToolsUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Redirect extends VulTaskImpl {

    public static List<String> REDIRECT_SCOPE = new ArrayList<>(); //重定向的参数
    static {
        REDIRECT_SCOPE.add("redirect");
        REDIRECT_SCOPE.add("redirect_url");
        REDIRECT_SCOPE.add("redirect_uri");
        REDIRECT_SCOPE.add("callback");
        REDIRECT_SCOPE.add("url");
        REDIRECT_SCOPE.add("goto");
        REDIRECT_SCOPE.add("callbackIframeUrl");
        REDIRECT_SCOPE.add("service");
    }

    boolean isBypass = false; //标记bypass，callback的时候可以判断

    public static VulTaskImpl getInstance(IHttpRequestResponse requestResponse){
        return new Redirect(requestResponse);
    }
    private Redirect(IHttpRequestResponse requestResponse) {
        super(requestResponse);
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、检查url参数是否包含回调函数字段
         * 2、有字段则添加字段在测试
         * */
        // 后缀检查，静态资源不做测试
        List<String> add = new ArrayList<String>();
        add.add(".js");
        if (!isStaticSource(BurpReqRespTools.getUrlPath(requestResponse), add)){
            //1.请求的url中含redirect敏感参数
            String query = BurpReqRespTools.getQuery(requestResponse);
            if (query != null) {
                List<String> payloads = new ArrayList<>();
                Map<String, Object> qm = BurpReqRespTools.getQueryMap(requestResponse);
                for (String paramname : qm.keySet()) {
                    if (REDIRECT_SCOPE.contains(paramname)) {
                        if (isBypass) {
                            payloads.addAll(getBypassPayload(paramname,qm.get(paramname).toString(), query));
                        } else {
                            payloads.addAll(getPayload(paramname,qm.get(paramname).toString(), query));
                        }
                    }
                }
                for (String payload_query : payloads) {
                    //新的请求包
                    okHttpRequester.send(
                        BurpReqRespTools.getUrlWithOutQuery(requestResponse), 
                        BurpReqRespTools.getMethod(requestResponse), 
                        BurpReqRespTools.getReqHeaders(requestResponse), 
                        payload_query, 
                        new String(BurpReqRespTools.getReqBody(requestResponse)), 
                        BurpReqRespTools.getContentType(requestResponse), 
                        new RedirectCallback(this));
                }
            }
        }
    }

    /**
     * 获取请求的payload
     * @param originValue 参数值
     * @param querystring 完整的
     * @return List<String>
     */
    private List<String> getPayload(String paranname, String originValue, String querystring){
        List<String> ret = new ArrayList<>();
        // 加载payload的模版
        String payload = "http://evil.com/";
        if (!originValue.equals("")) {
            // 将原参数值替换，形成新的querystring
            ret.add(querystring.replace(originValue, payload));
        } else {
            ret.add(querystring.replace(String.format("%s=",paranname), String.format("%s=%s",paranname, payload)));
        }

        return ret;
    }

    /**
     * 获取请求的payload,bypass
     * @param originValue 参数值
     * @param querystring 完整的
     * @return List<String>
     */
    private List<String> getBypassPayload(String paranname, String originValue, String querystring){
        List<String> ret = new ArrayList<>();
        // 获取原参数值中的域名,默认为当前请求的host:port,避免参数值是urlpath，获取不到域名的情况
        String originDomain = BurpReqRespTools.getHttpService(requestResponse).getHost() + ":" + BurpReqRespTools.getHttpService(requestResponse).getPort();
        Pattern domain_patern = Pattern.compile("(http[s]?:)?//(.*?)[/&\"]+?\\w*?");
        Matcher m_domain = domain_patern.matcher(originValue);
        if (m_domain.find()){
            originDomain = m_domain.group(2);
        }
        // 加载payload的模版
        List<String> payloads = SourceLoader.loadSources("/payloads/RedirectPayloadsTemplete.bbm");
        // 用于编码的特殊字符
        String[] encodeStr = new String[]{"@",":","/","://"};
        // 根据模版构造payload
        for (String templete : payloads) {
            if (!templete.startsWith("#") && !templete.equals("")) {
                String payload;
                if (!originValue.equals("")) {
                    // 将原参数值替换，形成新的querystring
                    payload = querystring.replace(originValue, templete.replaceAll("#domain#", originDomain));
                } else {
                    payload = querystring.replace(String.format("%s=", paranname), String.format("%s=%s", paranname, templete.replaceAll("#domain#", originDomain)));
                }
                // 处理#encode#的payload
                if (templete.contains("#encode#")) {
                    for (String s : encodeStr) {
                        // 将原参数值替换，形成新的querystring
                        payload = payload.replaceAll("#encode#", BurpExtender.helpers.urlEncode(s));
                    }
                }
                ret.add(payload);
            }
        }
        return ret;
    }
}

class RedirectCallback implements Callback {

    VulTaskImpl vulTask;

    public RedirectCallback(VulTaskImpl vulTask){
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
            Redirect.class.getSimpleName(),
            "onFailure", 
            "[RedirectCallback-onFailure] " + e.getMessage());
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        String message = null;
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call, response, vulTask.requestResponse);
        //检查响应头Location
        if (response.isRedirect()){
            String location = ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Location");
            if (location != null &&location.contains("evil.com")) {
                message = "Redirect";
            }
        }else if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains("evil.com")) { //检查响应体中，有些是页面加载后重定向
            message = "Redirect and inResp";
        }
        // 不为bypass才会进行绕过测试
        if (!((Redirect)vulTask).isBypass) {
            Redirect bypass = (Redirect) Redirect.getInstance(requestResponse);
            bypass.isBypass = true;
            bypass.start();
        }
        // 记录日志
        MainPanel.logAdd(
            requestResponse, 
            BurpReqRespTools.getHost(requestResponse), 
            BurpReqRespTools.getUrlPath(requestResponse),
            BurpReqRespTools.getMethod(requestResponse), 
            BurpReqRespTools.getStatus(requestResponse), 
            Redirect.class.getSimpleName(),
            message, 
            String.join("\n", SourceLoader.loadSources("/payloads/RedirectPayloadsTemplete.bbm")));
    }
}