package com.alumm0x.ui;

import com.alumm0x.engine.TaskManager;
import com.alumm0x.engine.VulScanner;
import com.alumm0x.listensers.HttpListener;
import com.alumm0x.util.ClassNameGet;
import com.alumm0x.util.CommonMess;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IRequestInfo;
import burp.IResponseInfo;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.*;
import java.util.List;


public class MainPanel {

    public static IMessageEditor requestViewer = null;
    public static IMessageEditor responseViewer = null;
    public static IMessageEditor desViewer = null;
    public static IHttpRequestResponse currentlyDisplayedItem = null;
    public static final List<LogEntry> log = new ArrayList<>(); // 记录漏洞的请求，在UI中展示
    public static Table logTable; //视图table对象
    // public static TableRowSorter<TableModel> sorter; //table排序对象
    public static boolean DEBUG = false; // debug模式，会记录所有请求
    
    public static boolean kg = false; //默认关闭
    public static JLabel lbConnectStatus; //插件运行状态
    public static JTextField tfFilterText; //过滤的条件输入框
    public static JTextField tfFilterText_c; //Cookie
    public static String domain = ".*";
    public static String cookie = "Cookie: xxx";
    // // 开启的任务列表-复选框
    public static final HashMap<String, Integer> intercepts = new HashMap<>();
    public static final List<JCheckBox> taskJBS = new ArrayList<>();

    public static Component getUI() {
        JPanel contentPane = new JPanel();

        // 整个UI
        contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        contentPane.setLayout(new BorderLayout(0, 0));

        // 设置的UI
        JPanel panel = new JPanel();
        FlowLayout flowLayout = (FlowLayout) panel.getLayout();
        flowLayout.setAlignment(FlowLayout.LEFT);
        // 设置：过滤的UI
        JButton btnFilter = new JButton("Domain");
        btnFilter.setPreferredSize(new Dimension(70,28)); // 按钮大小
        btnFilter.setToolTipText("配置扫描的域名,支持正则,填写后需点击此按钮");
        btnFilter.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                String d = tfFilterText.getText();
                if (null != d) {
                    MainPanel.domain = d;
                    BurpExtender.callbacks.printOutput("## Domain set: " + d);
                }else {
                    MainPanel.domain = ".*";
                }
            }
        });
        panel.add(btnFilter);
        tfFilterText = new JTextField();
        tfFilterText.setColumns(20);
        tfFilterText.setText(".*");
        panel.add(tfFilterText);

        JButton btnConn = new JButton("On-Off");
        btnConn.setPreferredSize(new Dimension(70,28)); // 按钮大小
        btnConn.setToolTipText("实时被动扫描器开关");
        btnConn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                MainPanel.OpenOrClose();
            }
        });
        panel.add(btnConn);

        JLabel lbConnectInfo = new JLabel("IsRun:");
        panel.add(lbConnectInfo);
        lbConnectStatus = new JLabel("False");
        lbConnectStatus.setForeground(new Color(255, 0, 0));
        panel.add(lbConnectStatus);

        JButton btnClear = new JButton("ClearTable");
        btnClear.setPreferredSize(new Dimension(90,28)); // 按钮大小
        btnClear.setToolTipText("清除数据，包含下表数据/请求队列/已测标记/请求缓存");
        btnClear.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                MainPanel.ClearResult();
            }
        });
        panel.add(btnClear);
        JButton btnrefresh = new JButton("RefreshTable");
        btnrefresh.setPreferredSize(new Dimension(100,28)); // 按钮大小
        btnrefresh.setToolTipText("刷新下表数据,执行完任务就刷刷，有时可能没收到数据变更的通知，导致下表没显示");
        btnrefresh.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                logTable.refreshTable();
            }
        });
        panel.add(btnrefresh);
        // scan功能
        JButton btnrescan = new JButton("Scan");
        btnrescan.setPreferredSize(new Dimension(70,28)); // 按钮大小
        btnrescan.setToolTipText("将以往记录的请求进行批量检测,检测勾选的task,会关闭被动扫描任务 (可通过'Show'查看已保存的请求)");
        btnrescan.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                if (lbConnectStatus.getText().equalsIgnoreCase("true")) {
                    MainPanel.OpenOrClose(); //关闭代理模式的扫描任务,前提是任务开启了（不要一边采集请求，一边扫描）
                }
                MainPanel.Scan(); //启动扫描
            }
        });
        panel.add(btnrescan);
        // 进度展示 all/over
        JLabel scantInfo = new JLabel("schedule:");
        panel.add(scantInfo);
        VulScanner.schedule = new JLabel(CommonMess.requests.size() + " / " + VulScanner.Over);
        VulScanner.schedule.setForeground(new Color(255, 0, 0));
        panel.add(VulScanner.schedule);
        // scan功能，显示所有保存的请求信息，清空列表，将请求都加入到列表中
        JButton scanshow = new JButton("Show");
        scanshow.setPreferredSize(new Dimension(70,28)); // 按钮大小
        scanshow.setToolTipText("显示所有保存的请求信息,将请求都加入到列表中,并且会显示当前任务进度，如果执行Scan的话");
        scanshow.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                MainPanel.Show(); //启动扫描
            }
        });
        panel.add(scanshow);
        JButton scanClear = new JButton("Clear");
        scanClear.setPreferredSize(new Dimension(70,28)); // 按钮大小
        scanClear.setToolTipText("清除保存的request");
        scanClear.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                CommonMess.requests.clear(); //开启的时候清空
                VulScanner.schedule.setText( "0 / 0");
                VulScanner.Over = 0;
                BurpExtender.callbacks.printOutput("Clear all requests");
            }
        });
        panel.add(scanClear);
        // debug开关的复选框
        JCheckBox debug = new JCheckBox("Debug");
        debug.setSelected(false); //默认不选中
        debug.addItemListener(new ItemListener() {

            @Override
            public void itemStateChanged(ItemEvent e) {
                JCheckBox cBox = (JCheckBox) e.getItem();// 将得到的事件强制转化为JCheckBox类
                DEBUG = false; // 默认关闭，勾选则开启
                if (cBox.isSelected()) {
                    DEBUG = true;
                }
                BurpExtender.callbacks.printOutput("## Debug=" + DEBUG);
            }
            
        }); //加入监听
        // gridBagLayout.setConstraints(button,constraints);
        panel.add(debug);
        // cookie设置
        JPanel panel_c = new JPanel();
        FlowLayout flowLayout_c = (FlowLayout) panel_c.getLayout();
        flowLayout_c.setAlignment(FlowLayout.LEFT);
        // 设置cookie的UI
        JButton btnFilter_c = new JButton("Cookie");
        btnFilter_c.setToolTipText("填写后需点击此按钮,才能设置Cookie,格式 cookie:xxx,token也可以");
        btnFilter_c.setPreferredSize(new Dimension(70,28)); // 按钮大小
        btnFilter_c.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                String d = tfFilterText_c.getText();
                if (null != d) {
                    cookie = d;
                }else {
                    cookie = "Cookie: xxx";
                }
            }
        });
        panel_c.add(btnFilter_c);
        tfFilterText_c = new JTextField();
        tfFilterText_c.setColumns(45);
        tfFilterText_c.setText("");
        panel_c.add(tfFilterText_c);
        JLabel note_c = new JLabel("注: 测试需要他人的会话凭证, eg:'Cookie: xxxxxx' 或是 'x-auth-token: xxx'.");
        note_c.setForeground(new Color(255, 0, 0));
        panel_c.add(note_c);
        //构造总设置UI
        JPanel panel_a = new JPanel();
        BoxLayout boxLayout = new BoxLayout(panel_a, BoxLayout.Y_AXIS);
        panel_a.setLayout(boxLayout);
        panel_a.add(panel);
        panel_a.add(panel_c);
        //添加设置的UI到总UI
        contentPane.add(panel_a, BorderLayout.NORTH);

        //下面是结果面板的ui
        //分割界面
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //上下分割
        contentPane.add(splitPane, BorderLayout.CENTER);

        //上面板，结果面板
        logTable = new Table(new MyTableModel());
        // 居中的样式
        DefaultTableCellRenderer render = new DefaultTableCellRenderer();
        render.setHorizontalAlignment(SwingConstants.CENTER);
        // 设置列宽
        TableColumnModel cm = logTable.getColumnModel();
        TableColumn id = cm.getColumn(0);
        id.setCellRenderer(render);
        id.setPreferredWidth(100);
        id.setMaxWidth(100);
        id.setMinWidth(50);
        id.setResizable(false);
        TableColumn host = cm.getColumn(1);
        host.setCellRenderer(render);
        host.setPreferredWidth(300);
        host.setMaxWidth(200);
        host.setMinWidth(50);
        TableColumn path = cm.getColumn(2);
        // path.setCellRenderer(render);F
        path.setPreferredWidth(300);
        path.setMaxWidth(300);
        path.setMinWidth(50);
        TableColumn method = cm.getColumn(3);
        method.setCellRenderer(render);
        method.setPreferredWidth(100);
        method.setMaxWidth(100);
        method.setMinWidth(50);
        method.setResizable(false);
        TableColumn status = cm.getColumn(4);
        status.setCellRenderer(render);
        status.setPreferredWidth(100);
        status.setMaxWidth(100);
        status.setMinWidth(50);
        status.setResizable(false);
        TableColumn plugin = cm.getColumn(5);
        plugin.setCellRenderer(render);
        plugin.setPreferredWidth(150);
        plugin.setMaxWidth(150);
        plugin.setMinWidth(50);
        plugin.setResizable(false);

//         //自定义排序逻辑，搞不明白算了，直接从数据源排序搞起
//         sorter = new TableRowSorter<>(BurpExtender.this);
//         List <RowSorter.SortKey> sortKeys
//                 = new ArrayList<>();
//         //设置默认排序的字段
//         sortKeys.add(new RowSorter.SortKey(2, SortOrder.ASCENDING));
//         //自定义比较器
//         Comparator<String> comparator = new Comparator<String>() {
//             public int compare(String s1, String s2) {
//                 return s1.compareTo(s2);
//             }
//         };
// //                sorter.setSortKeys(sortKeys);
//         sorter.setComparator(2, comparator);
//         logTable.setRowSorter(sorter);
//         //设置JTable的自动排序功能
// //                logTable.setAutoCreateRowSorter(true);

        JScrollPane scrollPane = new JScrollPane(logTable); //滚动条
        splitPane.setLeftComponent(scrollPane);

        //初始化下面板的Message对象
        requestViewer = BurpExtender.callbacks.createMessageEditor(BurpExtender.httpListener, false);
        responseViewer = BurpExtender.callbacks.createMessageEditor(BurpExtender.httpListener, false);
        desViewer = BurpExtender.callbacks.createMessageEditor(BurpExtender.httpListener, false);

        // 选中时显示请求跟响应
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Request", requestViewer.getComponent());
        tabs.addTab("Response", responseViewer.getComponent());
        tabs.addTab("Payload", desViewer.getComponent());

        splitPane.setRightComponent(tabs);

        // 搞个设置页面
        // 1.可以控制启动的任务
        // 1.1 为了可控，所以得设计个task管理器，对任务的添加及删除
        // 1.2 task搞成单例模式的话，就要考虑单个任务的全局变量的竞争，所以搞成队列式扫描模式，一个个跑
        // 1.2.1 收集请求对象
        // 1.2.2 并发池进行扫描，按单个请求去并发执行task（请求原始数据保存在Impl，新发起的请求数据保存在当前task）
        JPanel options = new JPanel();
        // 网格布局，两列，八列，后面随任务数增加而改变
        GridBagLayout gbaglayout=new GridBagLayout();    //创建GridBagLayout布局管理器
        GridBagConstraints constraints=new GridBagConstraints();
        options.setLayout(gbaglayout);    //使用GridBagLayout布局管理器
        constraints.fill=GridBagConstraints.BOTH;    //组件填充显示区域
        constraints.anchor = GridBagConstraints.NORTH; //组件的摆放位置
        constraints.weightx=0.0;    //恢复默认值
        constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
        JLabel intercept = new JLabel("Itercept");
        gbaglayout.setConstraints(intercept,constraints);
        options.add(intercept);
        constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
        makeItercept("proxy",options,gbaglayout,constraints);
        constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
        makeItercept("repeater",options,gbaglayout,constraints);
        constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
        JLabel task = new JLabel("Tasks");
        gbaglayout.setConstraints(task,constraints);
        options.add(task);
        constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
        // 添加复选框按钮
        makeButton("All",options,gbaglayout,constraints);
        constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
        makeButton("Collect",options,gbaglayout,constraints);
        constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
        makeButton("Api",options,gbaglayout,constraints);
        constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
        makeButton("Config",options,gbaglayout,constraints);
        constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
        makeButton("WebBasic",options,gbaglayout,constraints);
        constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
        makeButton("Cve",options,gbaglayout,constraints);
        constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
        for (String t : ClassNameGet.getClazzName("com.alumm0x.task", false)) {
            String[] l = t.split("\\.");
            constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
            makeButton(l[l.length - 1],options,gbaglayout,constraints);
        }

        // 添加到总UI
        contentPane.add(options, BorderLayout.EAST);

        return contentPane;
    }

    public static void makeItercept(String title,JPanel jPanel,GridBagLayout gridBagLayout,GridBagConstraints constraints)
    {
        JCheckBox button=new JCheckBox(title);
        button.setSelected(false); //默认不选中
        button.addItemListener(new MyItemListener()); //加入监听
        gridBagLayout.setConstraints(button,constraints);
        jPanel.add(button);
    }
    public static void makeButton(String title,JPanel jPanel,GridBagLayout gridBagLayout,GridBagConstraints constraints)
    {
        JCheckBox button=new JCheckBox(title);
        button.setSelected(false); //默认不选中
        button.addItemListener(new MyItemListener()); //加入监听
        gridBagLayout.setConstraints(button,constraints);
        jPanel.add(button);
        taskJBS.add(button);
    }

    private static void OpenOrClose(){
        // 如果现在close，则open，反之则close
        if(kg){
            lbConnectStatus.setText("False");
            kg = false;
            lbConnectStatus.setForeground(new Color(255,0,0));
            TaskManager.STATUS = false; //关闭扫描器任务线程
            TaskManager.reqQueue.clear(); //清空队列
        }else{
            lbConnectStatus.setText("True");
            kg = true;
            lbConnectStatus.setForeground(new Color(0,255,0));
            //开启扫描器任务线程
            TaskManager.STATUS = true; //状态设置为true，死循环
            //任务管理线程启动
            new TaskManager().start();
        }
    }
    //清空数据
    private static void ClearResult(){
        log.clear();
        //通知表格数据变更了
        logTable.refreshTable();
        TaskManager.vulsChecked.clear(); //清空标记
        HttpListener.localCache.clear(); //清空时清空缓存
        TaskManager.reqQueue.clear(); //清空待检的请求队列
        // 清空请求响应tab
        currentlyDisplayedItem = null;
        BurpExtender.callbacks.printOutput("clear cache success.");
    }

    //批量扫描
    private static void Scan(){
        VulScanner.schedule.setForeground(new Color(0, 255, 0));
        VulScanner.Over = 0; // 启动前初始化未0
        VulScanner scanner = new VulScanner();
        // 更新进度，https://xuexiyuan.cn/article/detail/239.html
        // UI更新必须在UI的线程中
        // fix:还是无法实时更新进度 (VulScanner必须继承Thread，如果是Runable就不行，看来这两种方式的多线程有差异)
        scanner.start();
    }

    //显示所有保存的请求
    private static void Show(){
        for (IHttpRequestResponse messageInfo :
                CommonMess.requests) {
            //返回信息
            IHttpService iHttpService = messageInfo.getHttpService();
            //请求信息
            IRequestInfo analyzeRequest = BurpExtender.helpers.analyzeRequest(messageInfo);
            IResponseInfo analyzeResponse = BurpExtender.helpers.analyzeResponse(messageInfo.getResponse());
            String host = iHttpService.getHost();
            String path = analyzeRequest.getUrl().getPath();
            String method = analyzeRequest.getMethod();
            short status = analyzeResponse.getStatusCode();
            boolean inside = false; // 标记是否已添加在列表中
            int row = log.size();
            // 重复的不显示
            for (LogEntry le :
                    log) {
                if (le.Host.equalsIgnoreCase(host)
                        && le.Path.equalsIgnoreCase(path)
                        && le.Method.equalsIgnoreCase(method)) {
                    inside = true;
                    break;
                }
            }
            if (!inside) {
                // log.add(new LogEntry(row, BurpExtender.callbacks.saveBuffersToTempFiles(messageInfo),
                //         host, path, method, status, "", ""));
            }

        }
        //通知表格数据变更了
        logTable.refreshTable();
        // 如果总数跟下表的数据不一致，说明存在重复的请求
        VulScanner.schedule.setText(CommonMess.requests.size() + " / " + VulScanner.Over);
    }

    // 添加面板展示数据
    // 已经在列表的不添加
    // 添加synchronized防止多线程竞态
    public static synchronized void logAdd(IHttpRequestResponse requestResponse, String host, String path, String method, short status, String plugin, String risk, String payloads) {
        int row = log.size();
        // debug模式则记录所有
        if (DEBUG) {
            try {
            log.add(new LogEntry(row, BurpExtender.callbacks.saveBuffersToTempFiles(requestResponse),
                    host, path, method, status, plugin, risk, payloads));
            } catch (Exception e) {
                BurpExtender.callbacks.printError("[Debug] MainPanel.logAdd " + e.getMessage());
            }
            //通知数据可能变更，刷新全表格数据，该用okhttp异步发包后，没办法同步调用fireTableRowsInserted通知刷新数据，因为一直row=lastRow
            MainPanel.logTable.refreshTable();
        } else if (risk != null && !risk.equals("onFailure") && !risk.equals("")) { // 非debug模式仅记录有风险的，及risk不为空
            boolean inside = false;
            for (LogEntry le :
                    log) {
                if (le.Host.equalsIgnoreCase(host)
                        && le.Path.equalsIgnoreCase(path)
                        && le.Method.equalsIgnoreCase(method)
                    //    && le.Status.equals(status)
                        && le.Risk.equalsIgnoreCase(risk)) {
                    inside = true;
                    break;
                }
            }
            if (!inside) {
                log.add(new LogEntry(row, BurpExtender.callbacks.saveBuffersToTempFiles(requestResponse),
                        host, path, method, status, plugin, risk, payloads));
                //通知数据可能变更，刷新全表格数据，该用okhttp异步发包后，没办法同步调用fireTableRowsInserted通知刷新数据，因为一直row=lastRow
                MainPanel.logTable.refreshTable();
            }
        }
    }
}
