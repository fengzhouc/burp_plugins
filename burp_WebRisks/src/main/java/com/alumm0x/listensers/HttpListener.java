package com.alumm0x.listensers;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.SwingUtilities;

import com.alumm0x.engine.TaskManager;
import com.alumm0x.engine.VulScanner;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.BurpReqRespTools;
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
            //检查插件是否开启
            String host = BurpReqRespTools.getHost(messageInfo);
            // callbacks.printOutput(host);
            Pattern pattern = Pattern.compile(MainPanel.domain);
            Matcher m = pattern.matcher(host);
            boolean m_host = m.find();
            if (MainPanel.kg && m_host) { //是否开启插件，开启后匹配设置的domain才会进行扫描
                String url = BurpReqRespTools.getUrl(messageInfo);
                // 构造请求的唯一标识
                String in = String.format("method_%s_url_%s_status_%d_body_%s", BurpReqRespTools.getMethod(messageInfo), url, BurpReqRespTools.getStatus(messageInfo), new String(BurpReqRespTools.getReqBody(messageInfo)));
                //计算MD5
                md.update(in.getBytes());
                String md5 = new BigInteger(1, md.digest()).toString(16);
                // 检查是否在缓存中
                if (localCache.get(md5) == null) { //如果在缓存中则返回
                    // 将请求放入队列
                    try {
                        TaskManager.reqQueue.put(messageInfo); //这里会阻塞
                        CommonMess.requests.add(messageInfo); //保存IHttpRequestResponse，用于批量扫描
                        // 同步刷新UI
                        SwingUtilities.invokeLater(new Runnable() {
                            @Override
                            public void run() {
                                // 更新scan进度
                                VulScanner.schedule.setText(CommonMess.requests.size() + " / 0");
                                MainPanel.logTable.refreshTable(); //刷新ui数据，以实时显示检测出得问题
                            }
                        });
                    } catch (InterruptedException e) {
                        BurpExtender.callbacks.printError("reqQueue.put -> " + e.getMessage());
                    }
                    //存入缓存中
                    localCache.put(md5, "in");
                }
                BurpExtender.callbacks.printOutput("inCache " + url);
            }
        }
    }
    
}
