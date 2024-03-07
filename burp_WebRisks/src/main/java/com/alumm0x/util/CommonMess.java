package com.alumm0x.util;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import java.util.ArrayList;
import java.util.List;

public class CommonMess {
    /**
     * 用于存储公共数据的
     */
    // 保存当前需要认证才能访问的IHttpRequestResponse（IDOR任务中保存），用于检测登出后是否失效会话
    public static IHttpRequestResponse authMessageInfo = null;
    // SmsEmailBoom次数计数
    public static int SmsEmailBoomCount = 0;
    // 记录所有IHttpRequestResponse，用于后续的扫描，比如越权扫描
    public static List<IHttpRequestResponse> requests = new ArrayList<>();

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
}
