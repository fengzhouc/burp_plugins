package com.alumm0x.engine;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.alumm0x.impl.VulTaskImpl;

import burp.BurpExtender;
import burp.IHttpRequestResponse;

// 扫描器，也就是消费队列中的请求，去执行一系列的task
// 1.1 起一个线程去运行，这样不影响burp的主流程
// 1.2 循环遍历队列的请求（需要阻塞队列，这样线程不会关闭，直到手动关闭），并发执行task，默认5线程
// 1.3 额外的，如果自定义请求管理及任务管理，那就不要用burp的被动扫描，这样我可以直接关了burp的被动扫描了，较少burp的消耗
public class TaskManager extends Thread {
    //线程状态记录
    List<Future<?>> threads; 
    //线程池
    public static  ExecutorService taskManagerthreadPool = null;
    //请求队列
    public static final ArrayBlockingQueue<IHttpRequestResponse> reqQueue = new ArrayBlockingQueue<>(2000);
    // 开启检测的任务清单
    public static final ArrayList<String> tasks = new ArrayList<String>();
    // 只需要检测一次的清单
    List<String> oneChecks = new ArrayList<>();
    // 检测后添加已检测标记，用于“oneChecks”的限制
    public static List<String> vulsChecked = new ArrayList<>(); 
    //taskManager的运行控制
    public static boolean STATUS = false; 
    public TaskManager(){
        // 创建一个固定大小4的线程池:
        taskManagerthreadPool = Executors.newFixedThreadPool(5);
        threads = new ArrayList<>();
        oneChecks.add("burp.vuls.oa.landray.LandrayOa");
        oneChecks.add("burp.vuls.shiro.ShiroUse");
        oneChecks.add("burp.task.Https");
        oneChecks.add("burp.task.api.SwaggerApi");
    }
    @Override
    public void run() {
        // 无限循环，但必须保证一个一个请求进行，不然单例模式的task里面的数据会乱
        while (STATUS) {
            try {
                // 这里会阻塞，如果没有请求进来的话
                IHttpRequestResponse messageInfo = reqQueue.take();
                // 并发控制，okhttp的并发太高了，不限制下，burp会很卡
                for (String taskClass : tasks) {
                    try {
                        // 如果是一次性的任务，则按域名加端口进行
                        if (oneChecks.contains(taskClass)){
                            String host = messageInfo.getHttpService().getHost();
                            int port = messageInfo.getHttpService().getPort();
                            if (vulsChecked.contains(taskClass + host + port)){
                                continue; //跳到下一个任务
                            }
                            // 添加标记的动作再具体的task中
                        }
                        @SuppressWarnings("rawtypes")
                        Class c = Class.forName(taskClass);
                        @SuppressWarnings("unchecked")
                        Method method = c.getMethod("getInstance", IHttpRequestResponse.class);
                        VulTaskImpl t = (VulTaskImpl) method.invoke(null, messageInfo);
                        // callbacks.printError("cehck " + task.getClass().getName());

                        Future<?> future = taskManagerthreadPool.submit(t); //添加到线程池执行
                        threads.add(future);

                    } catch (Exception e) {
                        BurpExtender.callbacks.printError("Class.forName -> " + e);
                    }
                }
                // 这里控制单个请求检测完之后，才会进入下一个请求的检测
                while (true){
                    boolean allDone = true;
                    for (Future<?> thread : threads) {
                        if (!thread.isDone()) {
                            // 只要有一个没完成就设置为false
                            allDone = false;
                            break;
                        }
                        //都完成了就会是true
                    }
                    if (allDone){
                        // 全部完成就退出while
                        break;
                    }
                }
            } catch (InterruptedException e) {
                BurpExtender.callbacks.printError("reqQueue.take() -> " + e);
            }
        }
    }
}

// TODO https://github.com/ilmila/J2EEScan.git 漏洞检测加入
// TODO 请求走私检测 https://xz.aliyun.com/t/6299
// TODO 缓存投毒