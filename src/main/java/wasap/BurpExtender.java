package wasap;

import burp.*;
import javax.swing.*;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private WaSAPPanel panel;
    private ScanController scanController;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.panel = new WaSAPPanel();
        this.scanController = new ScanController(callbacks, panel);

        callbacks.setExtensionName("WaSAP");
        callbacks.registerContextMenuFactory(this);
        callbacks.addSuiteTab(this);

        callbacks.printOutput("WaSAP - Web Application SAP Enumerator");
        callbacks.printOutput("--------------------------------------------------");
        callbacks.printOutput(
                "Simple burp plugin that checks for known endpoints and misconfigurations in SAP applications.");
    }

    @Override
    public String getTabCaption() {
        return "WaSAP";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuList = new ArrayList<>();
        JMenuItem menuItem = new JMenuItem("Enumerate SAP Endpoints");

        menuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                panel.clear();
                scanController.startScan(invocation);
            }
        });

        menuList.add(menuItem);
        return menuList;
    }
}
