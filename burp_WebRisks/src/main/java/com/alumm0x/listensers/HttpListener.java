package com.alumm0x.listensers;

import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.alumm0x.engine.TaskManager;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.CommonMess;
import com.alumm0x.util.LRUCache;

import burp.BurpExtender;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditorController;

public class HttpListener implements IHttpListener, IMessageEditorController {

    //本地缓存，存放已检测过的请求，检测过就不检测了
    @SuppressWarnings("rawtypes")
    public static  LRUCache localCache;
    private  MessageDigest md;

    @SuppressWarnings("rawtypes")
    public HttpListener() {
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            BurpExtender.callbacks.printError(e.getMessage());
        }
        localCache = new LRUCache(10000);
    }

    @Override
    public IHttpService getHttpService() {
        return MainPanel.currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return MainPanel.currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return MainPanel.currentlyDisplayedItem.getResponse();
    }

    @SuppressWarnings("unchecked")
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        //勾选了intercepts，及勾选了检查项，才采集请求
        if (!messageIsRequest && MainPanel.intercepts.containsValue(toolFlag)) {
            URL urlo = BurpExtender.helpers.analyzeRequest(messageInfo).getUrl();
            String url = urlo.toString();
            byte[] requestInfo = messageInfo.getRequest();
            //计算MD5
            md.update(requestInfo);
            String md5 = new BigInteger(1, md.digest()).toString(16);

            //检查插件是否开启
            String host = urlo.getHost();
            // callbacks.printOutput(host);
            Pattern pattern = Pattern.compile(MainPanel.domain);
            Matcher m = pattern.matcher(host);
            boolean m_host = m.find();
            if (MainPanel.kg && m_host) { //是否开启插件，开启后匹配设置的domain才会进行扫描
                // 检查是否在缓存中
                if (localCache.get(md5) == null) { //如果在缓存中则返回
                    // 将请求放入队列
                    try {
                        TaskManager.reqQueue.put(messageInfo); //这里会阻塞
                        CommonMess.requests.add(messageInfo); //保存IHttpRequestResponse，用于批量扫描
                    } catch (InterruptedException e) {
                        BurpExtender.callbacks.printOutput("reqQueue.put -> " + e);
                    }
                    //存入缓存中
                    localCache.put(md5, "in");
                }
                BurpExtender.callbacks.printOutput("inCache " + url);
            }
        }
    }
    
}
