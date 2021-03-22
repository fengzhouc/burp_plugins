package burp;


import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;


public class BurpExtender extends AbstractTableModel implements IBurpExtender, IHttpListener, ITab, IMessageEditorController, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    public PrintWriter stdout;
    private JPanel contentPane;
    private Table logTable; //视图table对象
    JComboBox comboBox;
    JComboBox comboBoxCve;
    IHttpRequestResponse messageInfo;
    // TODO 每次添加新的漏洞时，这里添加对应数据，type为对应的类名，cves为对应漏洞的方法名
    private String[] type = {"Struts"};
    private String[][] cves = {{"all", "CVE_2019_0230"}};

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        //回调对象
        this.callbacks = callbacks;
        //获取扩展helper与stdout对象
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        callbacks.setExtensionName("WebVuls");
        callbacks.registerContextMenuFactory(this);

        //创建UI
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
                //type的下拉框
                JLabel lbConnectInfo = new JLabel("Type:");
                comboBox = new JComboBox(type);
                comboBox.setToolTipText("what‘s type");
                //对应type的cve下拉框
                JLabel cve = new JLabel("CVE:");
                comboBoxCve = new JComboBox();
                comboBoxCve.setToolTipText("what‘s cve");
                // 为组合框的选择动作注册监听事件,当此组合框的选择有变化时,另一个组合框自动更新内容
                comboBox.addActionListener(e -> {
                    comboBoxCve.removeAllItems();
                    int index = comboBox.getSelectedIndex();
                    callbacks.printOutput(index + "");
                    for(int i=0; i<cves[index].length; i++) {

                        comboBoxCve.addItem(cves[index][i]);
                    }
                });
                panel.add(lbConnectInfo);
                panel.add(comboBox);
                panel.add(cve);
                panel.add(comboBoxCve);

                JButton btnConn = new JButton("Start");
                btnConn.setToolTipText("start checking payload");
                btnConn.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        BurpExtender.this.Start();
                    }
                });
                panel.add(btnConn);

                JButton btnClear = new JButton("Clear");
                btnClear.setToolTipText("clear all the result.");
                btnClear.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent arg0) {
                        BurpExtender.this.ClearResult();
                    }
                });
                panel.add(btnClear);
                //添加设置的UI到总UI
                contentPane.add(panel, BorderLayout.NORTH);

                JSplitPane splitPaneAll = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT); //上下分割
                contentPane.add(splitPaneAll, BorderLayout.CENTER);

                //下面是结果面板的ui
                //分割界面
                JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //上下分割
                splitPane.setDividerLocation(300);
                contentPane.add(splitPane, BorderLayout.CENTER);

                //上面板，结果面板
                logTable = new Table(BurpExtender.this);

                JScrollPane scrollPane = new JScrollPane(logTable); //滚动条
                splitPane.setLeftComponent(scrollPane);

                //下面板，请求响应的面板
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);


                //定制UI组件
                callbacks.customizeUiComponent(contentPane);
                callbacks.customizeUiComponent(panel);
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(tabs);

                //添加标签
                callbacks.addSuiteTab(BurpExtender.this);

                //加载插件输出默认信息
                String author = "alumm0x";

                callbacks.printOutput("#Author: "+author);
                callbacks.printOutput("#Task: JsonCsrfAndCors");

                //注册监听器
                callbacks.registerHttpListener(BurpExtender.this);
            }
        });


    }
    private void Start(){
        //TODO 启动检测，根据需要检测的内容,通过反射的方式
        String type = comboBox.getSelectedItem().toString();
        String cve = comboBoxCve.getSelectedItem().toString();
        try{
            Class clazz = Class.forName("burp.vuls." + type);
            // 初始化必要的变量并赋值
            Field helpers = clazz.getDeclaredField("helpers");
            Field callbacks = clazz.getDeclaredField("callbacks");
            Field log = clazz.getDeclaredField("log");
            Field messageInfo = clazz.getDeclaredField("messageInfo");
            helpers.set(null, this.helpers);
            callbacks.set(null, this.callbacks);
            log.set(null, this.log);
            messageInfo.set(null, this.messageInfo);
            // 检测所有漏洞
            if (cve.equalsIgnoreCase("all")){
                //获取本类的所有方法，存放入数组
                Method[] methods = clazz.getDeclaredMethods();
                for (Method method : methods) {
                    // 获取需要检测的漏洞对应的方法并执行
                    method.invoke(null);
                }
            }else {
                // 获取需要检测的漏洞对应的方法并执行
                Method method = clazz.getMethod(cve);
                method.invoke(null);
            }
        }catch (ClassNotFoundException | NoSuchMethodException e){

        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
        fireTableDataChanged();

    }
    //清空数据
    private void ClearResult(){
        log.clear();
        //通知表格数据变更了
        fireTableDataChanged();
    }

    // 这个方法就是插件添加到菜单中
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList<>(1);
        IHttpRequestResponse[] requestResponses = invocation.getSelectedMessages();
        messageInfo = requestResponses[0];
        JMenuItem menuItem = new JMenuItem("Send to WebVuls");
        menus.add(menuItem);
        //响应信息
        IHttpService iHttpService = messageInfo.getHttpService();
        IResponseInfo analyzeResponse = this.helpers.analyzeResponse(messageInfo.getResponse());
        short status_code = analyzeResponse.getStatusCode();
        //请求信息
        IRequestInfo analyzeRequest = this.helpers.analyzeRequest(messageInfo);
        //返回上面板信息
        String host = iHttpService.getHost();
        String path = analyzeRequest.getUrl().getPath();
        String method = analyzeRequest.getMethod();
        menuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // logTable.addRowSelectionInterval();
                int row = log.size();
                LogEntry logEntry = new LogEntry(row, callbacks.saveBuffersToTempFiles(messageInfo),
                        host, path, method, status_code, "Origin");
                log.add(logEntry);
                fireTableRowsInserted(row, row);
            }
        });
        return menus;
    }


    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    }


    public String getTabCaption() {
        return "WebVuls";
    }

    public Component getUiComponent() {
        return contentPane;
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
    public IHttpService getHttpService() {
        return null;
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
    public static class LogEntry
    {
        public final int id;
        final IHttpRequestResponsePersisted requestResponse;
        //final URL url;
        public final String Host;
        public final String Path;
        public final String Method;
        public final Short Status;
        public final String Risk;


        public LogEntry(int id, IHttpRequestResponsePersisted requestResponse, String host, String path, String method, Short status, String risk)
        {
            this.Status = status;
            this.id = id;
            this.requestResponse = requestResponse;
            //this.Url = url;
            this.Method = method;
            this.Path = path;
            this.Host = host;
            this.Risk = risk;
        }

    }

}
