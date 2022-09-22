package burp;

import burp.impl.VulResult;
import burp.impl.VulTaskImpl;
import burp.util.CommonMess;
import burp.util.LRUCache;
import org.jetbrains.annotations.NotNull;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BurpExtender extends AbstractTableModel implements IBurpExtender, IHttpListener, ITab, IMessageEditorController {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IMessageEditor desViewer;
    private final List<LogEntry> log = new ArrayList<>();
    private IHttpRequestResponse currentlyDisplayedItem;
    public PrintWriter stdout;
    private JPanel contentPane;
    private boolean kg = false; //默认关闭
    private JLabel lbConnectStatus; //插件运行状态
    private JLabel schedule; //Scan扫描任务的进度，all/over
    private int Over = 0; //Scan扫描任务完成的请求数
    private Table logTable; //视图table对象
    private TableRowSorter<TableModel> sorter; //table排序对象
    private JTextField tfFilterText; //过滤的条件输入框
    private JTextField tfFilterText_c; //Cookie
    private String domain = ".*";
    public static String cookie = "Cookie: xxx";
    public static List<String> vulsChecked = new ArrayList<>(); //是否已经检测cve漏洞
    private JSplitPane splitPane;

    private final HashMap<String, Integer> intercepts = new HashMap<>();
    //创建任务map
    private final HashMap<String, String> tasks = new HashMap<>();
    private final List<JCheckBox> taskJBS = new ArrayList<>();
    //本地缓存，存放已检测过的请求，检测过就不检测了
    private final LRUCache localCache = new LRUCache(10000);
    private final MessageDigest md = MessageDigest.getInstance("MD5");


    //请求队列
    private final ArrayBlockingQueue<IHttpRequestResponse> reqQueue = new ArrayBlockingQueue<>(2000);
    //线程池
    private ExecutorService threadPool;
    private boolean STATUS = false; //taskManager的运行控制


    public BurpExtender() throws NoSuchAlgorithmException {
    }


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        //回调对象
        this.callbacks = callbacks;
        //获取扩展helper与stdout对象
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        callbacks.setExtensionName("WebRisks");

        //创建UI，更新ui必须在ui的线程中
        // UI操作原则
        // 1.不要阻塞UI线程，也就是不要在主线程中操作UI
        // 2.另起线程操作UI，比如是继承Thread的哈，不要Runable
        // 3.所有UI操作都在SwingUtilities.invokeLater中进行
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
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
                            BurpExtender.this.domain = d;
                        }else {
                            BurpExtender.this.domain = ".*";
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
                        BurpExtender.this.OpenOrClose();
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
                        BurpExtender.this.ClearResult();
                    }
                });
                panel.add(btnClear);
                JButton btnrefresh = new JButton("RefreshTable");
                btnrefresh.setPreferredSize(new Dimension(100,28)); // 按钮大小
                btnrefresh.setToolTipText("刷新下表数据,执行完任务就刷刷，有时可能没收到数据变更的通知，导致下表没显示");
                btnrefresh.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        BurpExtender.this.refreshTable();
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
                            BurpExtender.this.OpenOrClose(); //关闭代理模式的扫描任务,前提是任务开启了（不要一边采集请求，一边扫描）
                        }
                        BurpExtender.this.Scan(); //启动扫描
                    }
                });
                panel.add(btnrescan);
                // 进度展示 all/over
                JLabel scantInfo = new JLabel("schedule:");
                panel.add(scantInfo);
                schedule = new JLabel(CommonMess.requests.size() + " / " + Over);
                schedule.setForeground(new Color(255, 0, 0));
                panel.add(schedule);
                // scan功能，显示所有保存的请求信息，清空列表，将请求都加入到列表中
                JButton scanshow = new JButton("Show");
                scanshow.setPreferredSize(new Dimension(70,28)); // 按钮大小
                scanshow.setToolTipText("显示所有保存的请求信息,将请求都加入到列表中,并且会显示当前任务进度，如果执行Scan的话");
                scanshow.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        BurpExtender.this.Show(); //启动扫描
                    }
                });
                panel.add(scanshow);
                JButton scanClear = new JButton("Clear");
                scanClear.setPreferredSize(new Dimension(70,28)); // 按钮大小
                scanClear.setToolTipText("清除保存的request");
                scanClear.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        CommonMess.requests.clear(); //开启的时候清空
                        schedule.setText( "0 / 0");
                        Over = 0;
                        callbacks.printOutput("Clear all requests");
                    }
                });
                panel.add(scanClear);
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
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //上下分割
                contentPane.add(splitPane, BorderLayout.CENTER);

                //上面板，结果面板
                logTable = new Table(BurpExtender.this);
//                //自定义排序逻辑，搞不明白算了，直接从数据源排序搞起
//                sorter = new TableRowSorter<>(BurpExtender.this);
//                List <RowSorter.SortKey> sortKeys
//                        = new ArrayList<>();
//                //设置默认排序的字段
//                sortKeys.add(new RowSorter.SortKey(2, SortOrder.ASCENDING));
//                //自定义比较器
//                Comparator<String> comparator = new Comparator<String>() {
//                    public int compare(String s1, String s2) {
//                        return s1.compareTo(s2);
//                    }
//                };
////                sorter.setSortKeys(sortKeys);
//                sorter.setComparator(2, comparator);
//                logTable.setRowSorter(sorter);
//                //设置JTable的自动排序功能
////                logTable.setAutoCreateRowSorter(true);

                JScrollPane scrollPane = new JScrollPane(logTable); //滚动条
                splitPane.setLeftComponent(scrollPane);

                //初始化下面板的Message对象
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                desViewer = callbacks.createMessageEditor(BurpExtender.this, false);

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
                makeButton("JsonCsrf",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("Cors",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("formCsrf",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("IDOR",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("IDOR_xy",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("Jsonp",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("Https",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("SecureHeader",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("SecureCookie",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("Redirect",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("IndexOf",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("SqlInject",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("XssReflect",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("SSRF",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("SensitiveApi",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("SensitiveMessage",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("UploadSecure",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("BeanParanInject",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("WebSocketHijacking",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("BypassAuthXFF",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("BypassAuth",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("Json3rd",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("MethodFuck",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("XssDomSource",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("XmlMaybe",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("SessionInvalid",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("SmsEmailBoom",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("Oa",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("Shiro",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("Spring",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("Tomcat",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                makeButton("OtherVul",options,gbaglayout,constraints);
                constraints.gridwidth = GridBagConstraints.REMAINDER;    //结束行
                // 添加到总UI
                contentPane.add(options, BorderLayout.EAST);

                //定制UI组件
                callbacks.customizeUiComponent(contentPane);
                callbacks.customizeUiComponent(panel_a);
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);

                //添加标签
                callbacks.addSuiteTab(BurpExtender.this);

                //加载插件输出默认信息
                String author = "alumm0x";

                callbacks.printOutput("#Author: "+author);
                callbacks.printOutput("#Github: https://github.com/fengzhouc/burp_plugins");

                //注册监听器
                callbacks.registerHttpListener(BurpExtender.this);
            }
        });
    }

    public void makeItercept(String title,JPanel jPanel,GridBagLayout gridBagLayout,GridBagConstraints constraints)
    {
        JCheckBox button=new JCheckBox(title);
        button.setSelected(false); //默认不选中
        button.addItemListener(new MyItemListener()); //加入监听
        gridBagLayout.setConstraints(button,constraints);
        jPanel.add(button);
    }
    public void makeButton(String title,JPanel jPanel,GridBagLayout gridBagLayout,GridBagConstraints constraints)
    {
        JCheckBox button=new JCheckBox(title);
        button.setSelected(false); //默认不选中
        button.addItemListener(new MyItemListener()); //加入监听
        gridBagLayout.setConstraints(button,constraints);
        jPanel.add(button);
        taskJBS.add(button);
    }

    private void OpenOrClose(){
        // 如果现在close，则open，反之则close
        if(kg){
            lbConnectStatus.setText("False");
            kg = false;
            lbConnectStatus.setForeground(new Color(255,0,0));
            STATUS = false; //关闭扫描器任务线程
            threadPool.shutdown(); //关闭线程池
            reqQueue.clear(); //清空队列
        }else{
            lbConnectStatus.setText("True");
            kg = true;
            lbConnectStatus.setForeground(new Color(0,255,0));
            //开启扫描器任务线程
            STATUS = true; //状态设置为true，死循环
            //任务管理线程启动
            new TaskManager().start();
        }
    }
    //清空数据
    private void ClearResult(){
        log.clear();
        //通知表格数据变更了
        refreshTable();
        vulsChecked.clear(); //清空标记
        localCache.clear(); //清空时清空缓存
        reqQueue.clear(); //清空待检的请求队列
        callbacks.printOutput("clear cache success.");
    }

    //批量扫描
    private void Scan(){
        schedule.setForeground(new Color(0, 255, 0));
        Over = 0; // 启动前初始化未0
        VulScanner scanner = new VulScanner();
        // 更新进度，https://xuexiyuan.cn/article/detail/239.html
        // UI更新必须在UI的线程中
        // fix:还是无法实时更新进度 (VulScanner必须继承Thread，如果是Runable就不行，看来这两种方式的多线程有差异)
        scanner.start();
    }

    //显示所有保存的请求
    private void Show(){
        for (IHttpRequestResponse messageInfo :
                CommonMess.requests) {
            //返回信息
            IHttpService iHttpService = messageInfo.getHttpService();
            //请求信息
            IRequestInfo analyzeRequest = this.helpers.analyzeRequest(messageInfo);
            IResponseInfo analyzeResponse = this.helpers.analyzeResponse(messageInfo.getResponse());
            String host = iHttpService.getHost();
            String path = analyzeRequest.getUrl().getPath();
            String method = analyzeRequest.getMethod();
            short status = analyzeResponse.getStatusCode();
            boolean inside = false;
            int row = log.size();
            // 重复的不显示
            for (BurpExtender.LogEntry le :
                    log) {
                if (le.Host.equalsIgnoreCase(host)
                        && le.Path.equalsIgnoreCase(path)
                        && le.Method.equalsIgnoreCase(method)) {
                    inside = true;
                    break;
                }
            }
            if (!inside) {
                log.add(new BurpExtender.LogEntry(row, callbacks.saveBuffersToTempFiles(messageInfo),
                        host, path, method, status, "", ""));
            }

        }
        //通知表格数据变更了
        refreshTable();
        // 如果总数跟下表的数据不一致，说明存在重复的请求
        schedule.setText(CommonMess.requests.size() + " / " + Over);
    }

    //通知已刷新表格数据
    public void refreshTable(){
        fireTableDataChanged();
    }

    public String getTabCaption() {
        return "WebRisks";
    }

    public Component getUiComponent() {
        return contentPane;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        //勾选了intercepts，及勾选了检查项，才采集请求
        if (!messageIsRequest && intercepts.containsValue(toolFlag)) {
            URL urlo = this.helpers.analyzeRequest(messageInfo).getUrl();
            String url = urlo.toString();
            byte[] requestInfo = messageInfo.getRequest();
            //计算MD5
            md.update(requestInfo);
            String md5 = new BigInteger(1, md.digest()).toString(16);

            //检查插件是否开启
            String host = urlo.getHost();
            // callbacks.printOutput(host);
            Pattern pattern = Pattern.compile(domain);
            Matcher m = pattern.matcher(host);
            boolean m_host = m.find();
            if (kg && m_host) { //是否开启插件，开启后匹配设置的domain才会进行扫描
                // 检查是否在缓存中
                if (localCache.get(md5) == null) { //如果在缓存中则返回
                    // 将请求放入队列
                    try {
                        reqQueue.put(messageInfo); //这里会阻塞
                        CommonMess.requests.add(messageInfo); //保存IHttpRequestResponse，用于批量扫描
                    } catch (InterruptedException e) {
                        callbacks.printOutput("reqQueue.put -> " + e);
                    }
                    //存入缓存中
                    localCache.put(md5, "in");
                }
                callbacks.printOutput("inCache " + url);
            }
            //通知数据可能变更，刷新全表格数据，该用okhttp异步发包后，没办法同步调用fireTableRowsInserted通知刷新数据，因为一直row=lastRow
            fireTableDataChanged();
            // TODO https://github.com/ilmila/J2EEScan.git 漏洞检测加入
            // TODO 请求走私检测 https://xz.aliyun.com/t/6299
            // TODO 缓存投毒
        }
    }

    /*
     * 下面是Table的一些方法，主要是结果面板的数据展示，可定制，修改如下数据即可
     * */
    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            LogEntry logEntry = log.get(logTable.convertRowIndexToModel(row));
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;
            desViewer.setMessage(logEntry.Desc.getBytes(), false);

            super.changeSelection(row, col, toggle, extend);
        }
    }
    //上面板结果的数量，log是存储检测结果的
    @Override
    public int getRowCount()
    {
        return log.size();
    }
    //结果面板的字段数量
    @Override
    public int getColumnCount()
    {
        return 6;
    }
    //结果面板字段的值
    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "Id";
            case 1:
                return "Host";
            case 2:
                return "Path";
            case 3:
                return "Method";
            case 4:
                return "Status";
            case 5:
                return "Risk";
            default:
                return "";
        }
    }
    //获取数据到面板展示
    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        // 解决setAutoCreateRowSorter排序后,获取row乱了,导致获取表中数据时出现异常
        LogEntry logEntry = log.get(logTable.convertRowIndexToModel(rowIndex));
        if (logEntry != null) {

            switch (columnIndex) {
                case 0:
                    return logEntry.id;
                case 1:
                    return logEntry.Host;
                case 2:
                    return logEntry.Path;
                case 3:
                    return logEntry.Method;
                case 4:
                    return logEntry.Status;
                case 5:
                    return logEntry.Risk;
                default:
                    return "";
            }
        }else {
            return "";
        }
    }

//    @Override
//    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
//        super.setValueAt(aValue, logTable.convertRowIndexToModel(rowIndex), columnIndex);
//    }
    @Override
    public Class<?> getColumnClass(int column) {
        switch (column) {
            case 0:
                return int.class;
            case 1:
            case 2:
            case 3:
            case 5:
                return String.class;
            case 4:
                return short.class;
            default:
                return Object.class;
        }
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return new byte[0];
    }

    @Override
    public byte[] getResponse() {
        return new byte[0];
    }

    //存在漏洞的url信息类
    //log.add(new LogEntry(id, callbacks.saveBuffersToTempFiles(messageInfo),
    //                            host,path,param,helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode()));
    public static class LogEntry implements Comparable
    {
        public final int id;
        final IHttpRequestResponsePersisted requestResponse;
        //final URL url;
        public final String Host;
        public final String Path;
        public final String Method;
        public final short Status;
        public final String Risk;
        public final String Desc;


        public LogEntry(int id, IHttpRequestResponsePersisted requestResponse, String host, String path, String method, short status, String risk, String desc)
        {
            this.Status = status;
            this.id = id;
            this.requestResponse = requestResponse;
            //this.Url = url;
            this.Method = method;
            this.Path = path;
            this.Host = host;
            this.Risk = risk;
            this.Desc = desc;
        }

        @Override
        public int compareTo(@NotNull Object o) {
            String p = ((LogEntry)o).Path;
            //如果相等则不动
            if (this.Path.equalsIgnoreCase(p)) {
                return -1;
            }
            //其他情况都返回小于的情况
            return -1;
        }
    }

    private class MyItemListener implements ItemListener {

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
                    taskClass = "burp.task.BeanParamInject";
                    break;
                case "BypassAuth":
                    taskClass = "burp.task.BypassAuth";
                    break;
                case "BypassAuthXFF":
                    taskClass = "burp.task.BypassAuthXFF";
                    break;
                case "Cors":
                    taskClass = "burp.task.Cors";
                    break;
                case "formCsrf":
                    taskClass = "burp.task.Csrf";
                    break;
                case "Https":
                    taskClass = "burp.task.Https";
                    break;
                case "IDOR":
                    taskClass = "burp.task.IDOR";
                    break;
                case "IDOR_xy":
                    taskClass = "burp.task.IDOR_xy";
                    break;
                case "IndexOf":
                    taskClass = "burp.task.IndexOf";
                    break;
                case "Json3rd":
                    taskClass = "burp.task.Json3rd";
                    break;
                case "JsonCsrf":
                    taskClass = "burp.task.JsonCsrf";
                    break;
                case "Jsonp":
                    taskClass = "burp.task.Jsonp";
                    break;
                case "MethodFuck":
                    taskClass = "burp.task.MethodFuck";
                    break;
                case "Redirect":
                    taskClass = "burp.task.Redirect";
                    break;
                case "SecureCookie":
                    taskClass = "burp.task.SecureCookie";
                    break;
                case "SecureHeader":
                    taskClass = "burp.task.SecureHeader";
                    break;
                case "SensitiveApi":
                    taskClass = "SensitiveApi";
                    break;
                case "SensitiveMessage":
                    taskClass = "burp.task.SensitiveMessage";
                    break;
                case "SqlInject":
                    taskClass = "burp.task.SqlInject";
                    break;
                case "Ssrf":
                    taskClass = "burp.task.Ssrf";
                    break;
                case "UploadSecure":
                    taskClass = "burp.task.UploadSecure";
                    break;
                case "WebSocketHijacking":
                    taskClass = "burp.task.WebSocketHijacking";
                    break;
                case "XmlMaybe":
                    taskClass = "burp.task.XmlMaybe";
                    break;
                case "XssDomSource":
                    taskClass = "burp.task.XssDomSource";
                    break;
                case "XssReflect":
                    taskClass = "burp.task.XssReflect";
                    break;
                case "SessionInvalid":
                    taskClass = "burp.task.SessionInvalid";
                    break;
                case "SmsEmailBoom":
                    taskClass = "burp.task.SmsEmailBoom";
                    break;
                case "Oa":
                    taskClass = "Oa";
                    break;
                case "PutJsp":
                    taskClass = "burp.vuls.tomcat.PutJsp";
                    break;
                case "Shiro":
                    taskClass = "Shiro";
                    break;
                case "Spring":
                    taskClass = "Spring";
                    break;
                case "Tomcat":
                    taskClass = "Tomcat";
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
                    for (JCheckBox t : taskJBS) {
                        t.setSelected(true);
                    }
                }else if (taskClass.equalsIgnoreCase("SensitiveApi")){
                    // api探测的集合
                    tasks.put("Swagger", "burp.task.api.SwaggerApi");
                    tasks.put("Liferay", "burp.task.api.LiferayAPI");
                    tasks.put("SpringBootActuator", "burp.task.api.SpringBootActuator");
                }else if (taskClass.equalsIgnoreCase("Oa")){
                    // 框架漏洞集合
                    tasks.put("LandrayOa", "burp.vuls.oa.landray.LandrayOa");
                    tasks.put("LandrayOaTreexmlRce", "burp.vuls.oa.landray.LandrayOaTreexmlRce");
                }else if (taskClass.equalsIgnoreCase("Shiro")){
                    // 框架漏洞集合
                    tasks.put("ShiroUse", "burp.vuls.shiro.ShiroUse");
                }else if (taskClass.equalsIgnoreCase("Spring")){
                    // 框架漏洞集合
                    tasks.put("Spring4Shell", "burp.vuls.spring.Spring4Shell");
                }else if (taskClass.equalsIgnoreCase("Tomcat")){
                    // 框架漏洞集合
                    tasks.put("CVE-2017-12615", "burp.vuls.tomcat.PutJsp");
                }else if (taskClass.equalsIgnoreCase("OtherVul")){
                    // 其他杂七杂八的
                    tasks.put("SnoopXss", "burp.vuls.other.SnoopXss");
                }else if (taskClass.equalsIgnoreCase("burp.task.SessionInvalid")) {
                    // 绑定IDOR跟SessionInvalid的关系，如果SessionInvalid开了，那IDOR也必须开
                    tasks.remove(key);
                    for (JCheckBox t : taskJBS) {
                        if (t.getText().equalsIgnoreCase("IDOR")) {
                            t.setSelected(true);
                            break;
                        }
                    }
                }else if (!taskClass.equalsIgnoreCase("intercepts")) {
                    tasks.put(key, taskClass);
                }else {
                    switch (key) {
                        case "proxy":
                            intercepts.put("proxy", callbacks.TOOL_PROXY);
                            break;
                        case "repeater":
                            intercepts.put("repeater", callbacks.TOOL_REPEATER);
                            break;
                    }
                }
            } else {
                // 去勾选，则从列表中删除
                if (taskClass.equalsIgnoreCase("all")){
                    for (JCheckBox t : taskJBS) {
                        t.setSelected(false);
                    }
                }else if (taskClass.equalsIgnoreCase("SensitiveApi")){
                    // api探测的集合
                    tasks.remove("Swagger", "burp.task.api.SwaggerApi");
                    tasks.remove("Liferay", "burp.task.api.LiferayAPI");
                    tasks.remove("SpringBootActuator", "burp.task.api.SpringBootActuator");
                }else if (taskClass.equalsIgnoreCase("Oa")){
                    // 框架漏洞集合
                    tasks.remove("LandrayOa", "burp.vuls.oa.landray.LandrayOa");
                    tasks.remove("LandrayOaTreexmlRce", "burp.vuls.oa.landray.LandrayOaTreexmlRce");
                }else if (taskClass.equalsIgnoreCase("Shiro")){
                    // 框架漏洞集合
                    tasks.remove("ShiroUse", "burp.vuls.shiro.ShiroUse");
                }else if (taskClass.equalsIgnoreCase("Tomcat")){
                    // 框架漏洞集合
                    tasks.remove("CVE-2017-12615", "burp.vuls.tomcat.PutJsp");
                }else if (taskClass.equalsIgnoreCase("OtherVul")){
                    // 其他杂七杂八的
                    tasks.remove("SnoopXss", "burp.vuls.other.SnoopXss");
                }else if (taskClass.equalsIgnoreCase("burp.task.IDOR")) {
                    // 绑定IDOR跟SessionInvalid的关系，如果IDOR关了，就把SessionInvalid也关了
                    tasks.remove(key);
                    for (JCheckBox t : taskJBS) {
                        if (t.getText().equalsIgnoreCase("SessionInvalid")) {
                            t.setSelected(false);
                            break;
                        }
                    }
                }else if (!taskClass.equalsIgnoreCase("intercepts")) {
                    tasks.remove(key);
                }else {
                    intercepts.remove(key);
                }
            }
        }
    }

    // 扫描器，也就是消费队列中的请求，去执行一系列的task
    // 1.1 起一个线程去运行，这样不影响burp的主流程
    // 1.2 循环遍历队列的请求（需要阻塞队列，这样线程不会关闭，直到手动关闭），并发执行task，默认5线程
    // 1.3 额外的，如果自定义请求管理及任务管理，那就不要用burp的被动扫描，这样我可以直接关了burp的被动扫描了，较少burp的消耗
    private class TaskManager extends Thread {
        List<Future<?>> threads; //线程状态记录
        List<String> oneChecks = new ArrayList<>();
        public TaskManager(){
            // 创建一个固定大小4的线程池:
            threadPool = Executors.newFixedThreadPool(5);
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
                    for (String taskClass : tasks.values()) {
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
                            Class c = Class.forName(taskClass);
                            Method method = c.getMethod("getInstance", IExtensionHelpers.class, IBurpExtenderCallbacks.class, List.class);
                            VulTaskImpl t = (VulTaskImpl) method.invoke(null, helpers, callbacks, log);
                            // callbacks.printError("cehck " + task.getClass().getName());
                            t.init(messageInfo); //初始化task的请求信息
                            Future<?> future = threadPool.submit(t); //添加到线程池执行
                            threads.add(future);

                        } catch (Exception e) {
                            callbacks.printError("Class.forName -> " + e);
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
                    callbacks.printError("reqQueue.take() -> " + e);
                }
            }
        }
    }

    private class VulScanner extends Thread {

        List<Future<?>> threads; //线程状态记录
        //线程池
        private final ExecutorService threadPool;
        public VulScanner(){
            // 创建一个固定大小5的线程池:
            threadPool = Executors.newFixedThreadPool(5);
            threads = new ArrayList<>();
        }
        @Override
        public void run() {
            // 遍历保存的所有请求
            for (IHttpRequestResponse messageInfo : CommonMess.requests) {
                // 并发控制，okhttp的并发太高了，不限制下，burp会很卡
                for (String taskClass : tasks.values()) {
                    try {
                        Class c = Class.forName(taskClass);
                        Method method = c.getMethod("getInstance", IExtensionHelpers.class, IBurpExtenderCallbacks.class, List.class);
                        VulTaskImpl t = (VulTaskImpl) method.invoke(null, helpers, callbacks, log);
                        // callbacks.printError("cehck " + task.getClass().getName());
                        t.init(messageInfo); //初始化task的请求信息
                        Future<?> future = threadPool.submit(t); //添加到线程池执行
                        threads.add(future);

                    } catch (Exception e) {
                        callbacks.printError("Class.forName -> " + e);
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
                                refreshTable(); //刷新ui数据，以实时显示检测出得问题
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
}
