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
        
        if (jcb.isSelected()) {// 判断是否被选择
            // 选中则创建对象，存入检查列表
            if (key.equalsIgnoreCase("All")){
                for (JCheckBox t : MainPanel.taskJBS) {
                    t.setSelected(true);
                }
            }else if (key.equalsIgnoreCase("Collect")){
                // 信息采集的类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.collect", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (key.equalsIgnoreCase("Api")){
                // 漏洞api的探测
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.api", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (key.equalsIgnoreCase("Config")){
                // 安全配置的检测
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.config", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (key.equalsIgnoreCase("WebBasic")){
                // web基础漏洞的检测类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.webbasic", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (key.equalsIgnoreCase("Cve")){
                // Cve漏洞的检测类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.cves", false)) {
                    TaskManager.tasks.add(task);
                }
            }else if (key.equalsIgnoreCase("SessionInvalid")) {
                // 绑定IDOR跟SessionInvalid的关系，如果SessionInvalid开了，那IDOR也必须开
                TaskManager.tasks.add("com.alumm0x.task.SessionInvalid");
                for (JCheckBox t : MainPanel.taskJBS) {
                    if (t.getText().equalsIgnoreCase("IDOR")) {
                        t.setSelected(true);
                        break;
                    }
                }
            }else if (!key.equalsIgnoreCase("proxy")) {
                MainPanel.intercepts.put("proxy", IBurpExtenderCallbacks.TOOL_PROXY);
            }else if (!key.equalsIgnoreCase("repeater")) {
                MainPanel.intercepts.put("repeater", IBurpExtenderCallbacks.TOOL_REPEATER);
            }else {
                // 其他勾选的就在这里处理，也就是task这个包下的检测类了（不含子包的）
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task", false)) {
                    String[] l = task.split("\\.");
                    if (key.equalsIgnoreCase(l[l.length - 1])) {
                        TaskManager.tasks.add(task);
                        break;
                    }
                }
            }
        } else {
            // 去勾选，则从列表中删除
            if (key.equalsIgnoreCase("All")){
                for (JCheckBox t : MainPanel.taskJBS) {
                    t.setSelected(false);
                }
            }else if (key.equalsIgnoreCase("Collect")){
                // 信息采集的类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.collect", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (key.equalsIgnoreCase("Api")){
                // 漏洞api的探测
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.api", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (key.equalsIgnoreCase("Config")){
                // 安全配置的检测
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.config", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (key.equalsIgnoreCase("WebBasic")){
                // web基础漏洞的检测类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.webbasic", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (key.equalsIgnoreCase("Cve")){
                // Cve漏洞的检测类
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task.cves", false)) {
                    TaskManager.tasks.remove(task);
                }
            }else if (key.equalsIgnoreCase("IDOR")) {
                // 绑定IDOR跟SessionInvalid的关系，如果SessionInvalid开了，那IDOR也必须开
                TaskManager.tasks.remove("com.alumm0x.task.IDOR");
                for (JCheckBox t : MainPanel.taskJBS) {
                    if (t.getText().equalsIgnoreCase("SessionInvalid")) {
                        t.setSelected(false);
                        break;
                    }
                }
            } else if (!key.equalsIgnoreCase("proxy") || !key.equalsIgnoreCase("repeater")) {
                // 其他勾选的就在这里处理，也就是task这个包下的检测类了（不含子包的）
                for (String task : ClassNameGet.getClazzName("com.alumm0x.task", false)) {
                    String[] l = task.split("\\.");
                    if (key.equalsIgnoreCase(l[l.length - 1])) {
                        TaskManager.tasks.remove(task);
                        break;
                    }
                }
            }else {
                MainPanel.intercepts.remove(key);
            }
        }
    }
}
