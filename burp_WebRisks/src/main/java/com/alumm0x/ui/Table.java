package com.alumm0x.ui;

import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

/*
    * 下面是Table的一些方法，主要是结果面板的数据展示，可定制，修改如下数据即可
    * */
public class Table extends JTable
{
    AbstractTableModel tableModel;
    
    public Table(AbstractTableModel tableModel)
    {
        super(tableModel);
        this.tableModel = tableModel;
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend)
    {
        LogEntry logEntry = MainPanel.log.get(MainPanel.logTable.convertRowIndexToModel(row));
        MainPanel.requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
        MainPanel.responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
        MainPanel.currentlyDisplayedItem = logEntry.requestResponse;
        MainPanel.desViewer.setMessage(logEntry.Desc.getBytes(), false);

        super.changeSelection(row, col, toggle, extend);
    }

    //通知已刷新表格数据
    public void refreshTable(){
        SwingUtilities.invokeLater(new Runnable() {

            @Override
            public void run() {
                tableModel.fireTableDataChanged();
            }
        });
    }
}
