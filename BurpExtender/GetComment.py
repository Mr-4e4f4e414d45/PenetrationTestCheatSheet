#!/usr/bin/env python
# -*- coding: utf-8 -*-

from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, ListSelectionModel
from javax.swing import JFrame, JScrollPane, JPanel, JList
from java.awt import BorderLayout, Dimension, Font
import re
import sys

class BurpExtender(IBurpExtender, IContextMenuFactory):
    COMMENT_MATCH = "([^:\'\"]//(.*)\n|<!--((.|\s)*?)-->|\/\*((.|\s)*?)\*\/)"

    def registerExtenderCallbacks(self, callbacks):
        
        sys.stdout = callbacks.getStdout()
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("GetComment")
        callbacks.registerContextMenuFactory(self)

        return

    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = []
        menuItem = JMenuItem("GetComment", actionPerformed=self.getComment)
        menuList.append(menuItem)

        return menuList

    def getComment(self, event):
        requestResponses = self.context.getSelectedMessages()

        for reqResp in requestResponses:
            response = reqResp.getResponse()
            
        if not response == None:

            responseBody = self.helpers.bytesToString(response)

            matchs = re.finditer(self.COMMENT_MATCH, responseBody)

            commentList = []
            for match in matchs:
                try :
                    commentList.append(match.groups()[0].decode('utf-8'))
                except :
                    commentList.append(match.groups()[0])

            frame = JFrame("Get Comment")
            frame.setDefaultCloseOperation(frame.DISPOSE_ON_CLOSE)

            frame.setSize(720, 530)
            frame.setLayout(BorderLayout())
            frame.setResizable(False);

            list = JList(commentList)
            list.selectionMode = ListSelectionModel.SINGLE_INTERVAL_SELECTION
            list.font = Font("Ｍenlo", Font.PLAIN, 12)

            scrollPane = JScrollPane(list)
            scrollPane.setPreferredSize(Dimension(700,500))

            panel = JPanel()
            panel.add(scrollPane)

            frame.add(panel, BorderLayout.CENTER)
            frame.setVisible(True)
        else:
            pass
