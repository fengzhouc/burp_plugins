package com.alumm0x.engine;

import java.awt.Color;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.swing.JLabel;
import javax.swing.SwingUtilities;

import com.alumm0x.impl.VulTaskImpl;
import com.alumm0x.ui.MainPanel;
import com.alumm0x.util.CommonMess;

import burp.BurpExtender;
import burp.IHttpRequestResponse;

/*
 * VulScanner是一个主动对历史的请求进行扫描的引擎
 */
public class VulScanner extends Thread {

    List<Future<?>> threads; //线程状态记录
    // 线程池
    public final ExecutorService vulScannerthreadPool;
    // Scan扫描任务的进度，all/over
    public static JLabel schedule; 
    // Scan扫描任务完成的请求数
    public static int Over = 0; 

    public VulScanner(){
        // 创建一个固定大小5的线程池:
        vulScannerthreadPool = Executors.newFixedThreadPool(5);
        threads = new ArrayList<>();
    }
    @Override
    public void run() {
        // 遍历保存的所有请求
        for (IHttpRequestResponse messageInfo : CommonMess.requests) {
            // 并发控制，okhttp的并发太高了，不限制下，burp会很卡
            for (String taskClass : TaskManager.tasks) {
                try {
                    @SuppressWarnings("rawtypes")
                    Class c = Class.forName(taskClass);
                    @SuppressWarnings("unchecked")
                    Method method = c.getMethod("getInstance", IHttpRequestResponse.class);
                    VulTaskImpl t = (VulTaskImpl) method.invoke(null, messageInfo);
                    // callbacks.printError("cehck " + task.getClass().getName());
 
                    Future<?> future = vulScannerthreadPool.submit(t); //添加到线程池执行
                    threads.add(future);

                } catch (Exception e) {
                    BurpExtender.callbacks.printError("Class.forName -> " + e);
                }
            }
            // 这里控制单个请求检测完之后，才会进入下一个请求的检测
            while (true) {
                boolean allDone = true;
                for (Future<?> thread : threads) {
                    if (!thread.isDone()) {
                        // 只要有一个没完成就设置为false
                        allDone = false;
                        break;
                    }
                    //都完成了就会是true
                }
                if (allDone) {
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            // 更新scan进度
                            schedule.setText(CommonMess.requests.size() + " / " + (++Over));
                            MainPanel.logTable.refreshTable(); //刷新ui数据，以实时显示检测出得问题
                        }
                    });
                    // 全部完成就退出while
                    break;
                }
            }
        }
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // 跟改运行状态
                schedule.setForeground(new Color(255, 0, 0));
            }
        });
    }
}
