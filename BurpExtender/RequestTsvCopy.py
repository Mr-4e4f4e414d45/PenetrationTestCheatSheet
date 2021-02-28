#!/usr/bin/env python
# -*- coding: utf-8 -*-

from burp import IBurpExtender, IContextMenuFactory, IRequestInfo, IParameter
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import Clipboard
from java.awt.datatransfer import StringSelection
import sys

class BurpExtender(IBurpExtender, IContextMenuFactory, IRequestInfo, IParameter):
    def registerExtenderCallbacks(self, callbacks):
        
        sys.stdout = callbacks.getStdout()
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("RequestCopyTsv")
        callbacks.registerContextMenuFactory(self)

        return

    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = []
        menuItem = JMenuItem("RequestTsvCopy [URL/QueryString]", actionPerformed=self.getUrlAndQueryString)
        menuList.append(menuItem)

        return menuList

    def getUrlAndQueryString(self, event):
        requestResponses = self.context.getSelectedMessages()

        for reqResp in requestResponses:
            request = reqResp.getRequest()
            url = reqResp.getUrl()
            response = reqResp.getResponse()

        requestInfo = self.helpers.analyzeRequest(request)

        parameters = requestInfo.getParameters()
        paramlist = []
        for parameter in parameters:
            if parameter.getType() == IParameter.PARAM_BODY or parameter.getType() == IParameter.PARAM_URL or parameter.getType() == IParameter.PARAM_JSON:

                paramInfo = {}
                if parameter.getType() == IParameter.PARAM_BODY:
                    paramInfo["type"] = "BODY"
                
                if parameter.getType() == IParameter.PARAM_URL:
                    paramInfo["type"] = "URL"
                
                if parameter.getType() == IParameter.PARAM_JSON:
                    paramInfo['type'] = "JSON"

                paramInfo["name"] = parameter.getName()
                paramInfo["value"] = parameter.getValue()
                paramlist.append(paramInfo)

        clipboardInfo = {}
        clipboardInfo["url"] = url
        clipboardInfo["paramInfo"] = paramlist
        
        tsvFormat = self.createTsvFormat(clipboardInfo)

        toolkit = Toolkit.getDefaultToolkit()
        clipboard = toolkit.getSystemClipboard()
        clipboard.setContents(StringSelection(tsvFormat), None)

    def createTsvFormat(self, paramInfo):
        temp = ""
        for param in paramInfo["paramInfo"]:
            temp += "\t" + str(param["type"].encode('utf-8'))
            temp += "\t" + str(param["name"].encode('utf-8'))
            temp += "\t" + str(param["value"].encode('utf-8')) 
            temp += "\r\n"

        tsvFormat = "{}\r\n{}".format(paramInfo["url"], temp)

        return str(tsvFormat)
