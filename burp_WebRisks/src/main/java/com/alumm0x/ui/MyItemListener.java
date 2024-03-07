package com.alumm0x.ui;

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import javax.swing.JCheckBox;

import com.alumm0x.engine.TaskManager;
import com.alumm0x.util.ClassNameGet;

import burp.IBurpExtenderCallbacks;

public class MyItemListener implements ItemListener {

    public void itemStateChanged(ItemEvent e) {
        JCheckBox jcb = (JCheckBox) e.getItem();// 将得到的事件强制转化为JCheckBox类
        String key = jcb.getText(); //任务的名称
        String taskClass = ""; //task的类名
        //task跟类的映射
        switch (key) {
            case "All":
                taskClass = "all";
                break;
            case "BeanParamInject":
                taskClass = "com.alumm0x.task.BeanParamInject";
                break;
            case "BypassAuth":
                taskClass = "com.alumm0x.task.BypassAuth";
                break;
            case "BypassAuthXFF":
                taskClass = "com.alumm0x.task.BypassAuthXFF";
                break;
            case "Cors":
                taskClass = "com.alumm0x.task.Cors";
                break;
            case "formCsrf":
                taskClass = "com.alumm0x.task.Csrf";
                break;
            case "Https":
                taskClass = "com.alumm0x.task.Https";
                break;
            case "IDOR":
                taskClass = "com.alumm0x.task.IDOR";
                break;
            case "IDOR_xy":
                taskClass = "com.alumm0x.task.IDOR_xy";
                break;
            case "IndexOf":
                taskClass = "com.alumm0x.task.IndexOf";
                break;
            case "Json3rd":
                taskClass = "com.alumm0x.task.Json3rd";
                break;
            case "JsonCsrf":
                taskClass = "com.alumm0x.task.JsonCsrf";
                break;
            case "Jsonp":
                taskClass = "com.alumm0x.task.Jsonp";
                break;
            case "MethodFuck":
                taskClass = "com.alumm0x.task.MethodFuck";
                break;
            case "Redirect":
                taskClass = "com.alumm0x.task.Redirect";
                break;
            case "SecureCookie":
                taskClass = "com.alumm0x.task.SecureCookie";
                break;
            case "SecureHeader":
                taskClass = "com.alumm0x.task.SecureHeader";
                break;
            case "SensitiveApi":
                taskClass = "SensitiveApi";
                break;
            case "SensitiveMessage":
                taskClass = "com.alumm0x.task.SensitiveMessage";
                break;
            case "SqlInject":
                taskClass = "com.alumm0x.task.SqlInject";
                break;
            case "Ssrf":
                taskClass = "com.alumm0x.task.Ssrf";
                break;
            case "UploadSecure":
                taskClass = "com.alumm0x.task.UploadSecure";
                break;
            case "WebSocketHijacking":
                taskClass = "com.alumm0x.task.WebSocketHijacking";
                break;
            case "XmlMaybe":
                taskClass = "com.alumm0x.task.XmlMaybe";
                break;
            case "XssDomSource":
                taskClass = "com.alumm0x.task.XssDomSource";
                break;
            case "XssReflect":
                taskClass = "com.alumm0x.task.XssReflect";
                break;
            case "SessionInvalid":
                taskClass = "com.alumm0x.task.SessionInvalid";
                break;
            case "SmsEmailBoom":
                taskClass = "com.alumm0x.task.SmsEmailBoom";
                break;
            case "Oa":
                taskClass = "Oa";
                break;
            case "PutJsp":
                taskClass = "com.alumm0x.vuls.tomcat.PutJsp";
                break;
            case "Shiro":
                taskClass = "Shiro";
                break;
            case "Spring":
                taskClass = "Spring";
                break;
            case "OtherVul":
                taskClass = "OtherVul";
                break;
            default:
                taskClass = "intercepts";
        }
        if (jcb.isSelected()) {// 判断是否被选择
            // 选中则创建对象，存入检查列表
            if (taskClass.equalsIgnoreCase("all")){
                for (JCheckBox t : MainPanel.taskJBS) {
                    t.setSelected(true);
                }
            }else if (taskClass.equalsIgnoreCase("SensitiveApi")){
                // api探测的集合
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.api", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (taskClass.equalsIgnoreCase("Oa")){
                // 框架漏洞集合
                for (String task : ClassNameGet.getClazzName("com.alumm0x.vuls.oa", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (taskClass.equalsIgnoreCase("Shiro")){
                // 框架漏洞集合
                for (String task : ClassNameGet.getClazzName("com.alumm0x.vuls.shiro", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (taskClass.equalsIgnoreCase("Spring")){
                // 框架漏洞集合
                for (String task : ClassNameGet.getClazzName("com.alumm0x.vuls.spring", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (taskClass.equalsIgnoreCase("OtherVul")){
                // 其他杂七杂八的
                for (String task : ClassNameGet.getClazzName("com.alumm0x.vuls.other", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (taskClass.equalsIgnoreCase("com.alumm0x.task.SessionInvalid")) {
                // 绑定IDOR跟SessionInvalid的关系，如果SessionInvalid开了，那IDOR也必须开
                TaskManager.tasks.add(taskClass);
                for (JCheckBox t : MainPanel.taskJBS) {
                    if (t.getText().equalsIgnoreCase("IDOR")) {
                        t.setSelected(true);
                        break;
                    }
                }
            // 其他任务就在这里添加到任务清单中
            }else if (!taskClass.equalsIgnoreCase("intercepts")) {
                TaskManager.tasks.add(taskClass);
            }else {
                switch (key) {
                    case "proxy":
                        MainPanel.intercepts.put("proxy", IBurpExtenderCallbacks.TOOL_PROXY);
                        break;
                    case "repeater":
                        MainPanel.intercepts.put("repeater", IBurpExtenderCallbacks.TOOL_REPEATER);
                        break;
                }
            }
        } else {
            // 去勾选，则从列表中删除
            if (taskClass.equalsIgnoreCase("all")){
                for (JCheckBox t : MainPanel.taskJBS) {
                    t.setSelected(false);
                }
            }else if (taskClass.equalsIgnoreCase("SensitiveApi")){
                // api探测的集合
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.api", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (taskClass.equalsIgnoreCase("Oa")){
                // 框架漏洞集合
                for (String task : ClassNameGet.getClazzName("com.alumm0x.vuls.oa", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (taskClass.equalsIgnoreCase("Shiro")){
                // 框架漏洞集合
                for (String task : ClassNameGet.getClazzName("com.alumm0x.vuls.shiro", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (taskClass.equalsIgnoreCase("OtherVul")){
                // 其他杂七杂八的
                for (String task : ClassNameGet.getClazzName("com.alumm0x.vuls.other", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (taskClass.equalsIgnoreCase("com.alumm0x.task.IDOR")) {
                // 绑定IDOR跟SessionInvalid的关系，如果IDOR关了，就把SessionInvalid也关了
                TaskManager.tasks.remove(taskClass);
                for (JCheckBox t : MainPanel.taskJBS) {
                    if (t.getText().equalsIgnoreCase("SessionInvalid")) {
                        t.setSelected(false);
                        break;
                    }
                }
            }else if (!taskClass.equalsIgnoreCase("intercepts")) {
                TaskManager.tasks.remove(taskClass);
            }else {
                MainPanel.intercepts.remove(key);
            }
        }
    }
}
