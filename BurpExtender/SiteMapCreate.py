#!/usr/bin/env python
# -*- coding: utf-8 -*-

from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JFileChooser, JFrame, JPanel
from java.awt import BorderLayout
from javax.swing import JOptionPane
import json
import urlparse
import csv
import cgi
import io


NAME = 0
VALUE = 1
JSON_NAME = -2
JSON_VALUE = -1
NAME_ONLY = 1
NAME_AND_VALUE = 2
LOCATION_STATUS_COMMIT = "commit"
LOCATION_STATUS_NOMAL = "target"
LOCATION_STATUS_DUPLICATE = "duplicate"
COMMIT = "commit:"
SET_DIALOG_TITLE = "Select Export Location"
SHOW_MESSAGE_DIALOG_WARNING = "Please select a file."
WARNING = "Warning"
SHOW_MESSAGE_DIALOG_INFORMATION = "File creation is complete."
COMPLEATE = "Compleate"
SHOW_MESSAGE_DIALOG_ERROR = "An error has occurred. Please check your files."
ERROR = "Error"
BODY_PARAM = "BODY"
QUERY_PARAM = "URL"
JSON_PARAM = "JSON"

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        sys.stdout = callbacks.getStdout()
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("SiteMapCreate")
        callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = []
        menuItem = JMenuItem("SiteMapCreate", actionPerformed=self.main)
        menuList.append(menuItem)
        return menuList

    def main(self, event):
        frame = JFrame("") 
        fileChooser = JFileChooser()
        fileChooser.setDialogTitle(SET_DIALOG_TITLE)
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        fileChooser.showOpenDialog(fileChooser)
        file = fileChooser.getSelectedFile()
        path = str(file)

        if path == "None":
            JOptionPane.showMessageDialog(frame, SHOW_MESSAGE_DIALOG_WARNING, WARNING, JOptionPane.WARNING_MESSAGE)
            return

        try:
            jsonOpen = open(path, 'r')
            jsonLoad = json.load(jsonOpen)
            siteMapLists = self.siteMapCreate(jsonLoad)
            self.csvCreate(siteMapLists)
            JOptionPane.showMessageDialog(frame, SHOW_MESSAGE_DIALOG_INFORMATION, COMPLEATE, JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(frame, SHOW_MESSAGE_DIALOG_ERROR, ERROR, JOptionPane.ERROR_MESSAGE)

    def jsonDictGenerator(self, jsonDic, pre=None):
        pre = pre[:] if pre else []
        if isinstance(jsonDic, dict):
            for key, value in jsonDic.items():
                if isinstance(value, dict):
                    for dic in self.jsonDictGenerator(value, pre + [key]):
                        yield dic
                elif isinstance(value, list) or isinstance(value, tuple):
                    for val in value:
                        for dic in self.jsonDictGenerator(val, pre + [key]):
                            yield dic
                else:
                    yield pre + [key, value]
        else:
            yield pre + [jsonDic]


    def duplicateCheck(self, siteMapLists):
        tmp = []
        for siteMap in siteMapLists:
            for duplicateCheck in siteMapLists:
                if siteMap != duplicateCheck:
                    if duplicateCheck['Path'] == siteMap['Path'] and 'Path' in siteMap:
                        queryParamTmpSiteMap = []
                        queryParamTmpDuplicate = []
                        bodyParamTmpSiteMap = []
                        bodyParamTmpDuplicate = []
                        jsonParamTmpSiteMap = []
                        jsonParamTmpDuplicate = []
                        if len(siteMap['QueryParam']) != 0:
                            for paramQuery in siteMap['QueryParam']:
                                queryParamTmpSiteMap.append(paramQuery[NAME])

                        if len(duplicateCheck['QueryParam']) != 0:
                            for paramDupQuery in duplicateCheck['QueryParam']:
                                queryParamTmpDuplicate.append(paramDupQuery[NAME])

                        if len(siteMap['BodyParam']) != 0:
                            for paramBody in siteMap['BodyParam']:
                                bodyParamTmpSiteMap.append(paramBody[NAME])

                        if len(duplicateCheck['BodyParam']) != 0:
                            for paramDupBody in duplicateCheck['BodyParam']:
                                bodyParamTmpDuplicate.append(paramDupBody[NAME])

                        if len(siteMap['JsonParam']) != 0:
                            for paramJson in siteMap['JsonParam']:
                                jsonParamTmpSiteMap.append(paramJson[NAME])

                        if len(duplicateCheck['JsonParam']) != 0:
                            for paramDupJson in duplicateCheck['JsonParam']:
                                jsonParamTmpDuplicate.append(paramDupJson[NAME])

                        siteMapParams = queryParamTmpSiteMap + bodyParamTmpSiteMap + jsonParamTmpSiteMap
                        siteMapParams = sorted(siteMapParams)
                        siteMapParams = "".join(siteMapParams)

                        duplicateCheckParams = queryParamTmpDuplicate + bodyParamTmpDuplicate + jsonParamTmpDuplicate
                        duplicateCheckParams = sorted(duplicateCheckParams)
                        duplicateCheckParams = "".join(duplicateCheckParams)

                        if siteMapParams == duplicateCheckParams:
                            siteMap["status"] = LOCATION_STATUS_DUPLICATE


            tmp.append(siteMap)
        return tmp

    def csvCreate(self, siteMapLists):
        file = open('SiteMap.csv', 'w')
        csv_file = csv.writer(file)
        for siteMap in siteMapLists:
            csvTmp =[]
            csvParamTmp = []
            try:
                if COMMIT in siteMap["location"]:
                    siteMap["location"] = siteMap["location"].replace(COMMIT, "")
                    csvTmp.append(LOCATION_STATUS_COMMIT)
                elif LOCATION_STATUS_DUPLICATE in siteMap["status"]:
                    csvTmp.append(LOCATION_STATUS_DUPLICATE)
                else:
                    csvTmp.append(LOCATION_STATUS_NOMAL)

                csvTmp.append(siteMap["location"].encode('utf-8'))
                csvTmp.append(siteMap["url"].encode('utf-8'))

                for queryParams in siteMap["QueryParam"]:
                    paramTmp = ["", "", "", QUERY_PARAM]
                    if len(queryParams) == NAME_AND_VALUE:
                        queryParamName = self.paramEncode(queryParams[NAME])
                        queryParamValue = self.paramEncode(queryParams[VALUE])
                        paramTmp.append(queryParamName)
                        paramTmp.append(queryParamValue)
                    elif len(queryParams) == NAME_ONLY:
                        queryParamName = self.paramEncode(queryParams[NAME])
                        paramTmp.append(queryParamName)

                    csvParamTmp.append(paramTmp)

                for bodyParams in siteMap["BodyParam"]:
                    paramTmp = ["", "", "", BODY_PARAM]
                    if len(bodyParams) == NAME_AND_VALUE:
                        bodyParamName = self.paramEncode(bodyParams[NAME])
                        bodyParamValue = self.paramEncode(bodyParams[VALUE])
                        paramTmp.append(bodyParamName)
                        paramTmp.append(bodyParamValue)
                    elif len(bodyParams) == NAME_ONLY:
                        bodyParamName = self.paramEncode(bodyParams[NAME])
                        paramTmp.append(bodyParamName)
            
                    csvParamTmp.append(paramTmp)

                for jsonParams in siteMap["JsonParam"]:

                    jsonParamName = self.paramEncode(jsonParams[NAME])
                    jsonParamVaule = self.paramEncode(jsonParams[VALUE])
                    paramTmp = ["", "", "", JSON_PARAM]
                    paramTmp.append(jsonParamName)
                    paramTmp.append(jsonParamVaule)
                    csvParamTmp.append(paramTmp)

            except Exception as e:
                    csvTmp =[]
                    csvTmp.append(ERROR)
                    break
                    if 'location' in siteMap:
                        csvTmp.append(siteMap['location'].encode('utf-8'))
                    if 'url' in siteMap:
                        csvTmp.append(siteMap['url'].encode('utf-8'))
                    #csvTmp.append(e)

            csv_file.writerow(csvTmp)

            for csvParam in csvParamTmp:
                try:
                    csv_file.writerow(csvParam)
                except ValueError as e:
                    error = ["Error"]
                    csv_file.writerow(error) 

        file.close()

    def paramEncode(self, param):
        param = param.encode('utf-8') if type(param) == "unicode" else param

        return param

    def queryParamList(self, queryParams):  
        queryParams = queryParams.replace('?', '').split('&')
        queryParamList = []
        for queryParam in queryParams:
            queryParam = queryParam.split("=", 1)
            queryParamList.append(queryParam)

        return queryParamList

    def multipart(self, requestInfo):
        fp = io.BytesIO(requestInfo["Request"]["Body"].encode('utf-8'))
        environ = {"REQUEST_METHOD": "POST"}
        headers = {
            "content-type" : requestInfo["Request"]["ContentType"],
            "content-length" : requestInfo["Request"]["Length"]
        }
        multipartParams = cgi.FieldStorage(fp = fp, environ = environ, headers = headers)

        multipartParamList = []
        for param in multipartParams.list:
            multipartParam = []
            multipartParam.append(param.name)
            multipartParam.append(param.value)
            multipartParamList.append(multipartParam)

        return multipartParamList
  
    def jsonParam(self, jsonParam):
        jsonParamList = []
        try:
            jsonDic = json.loads(jsonParam)
            jsonNameValues = list(self.jsonDictGenerator(jsonDic, []))
            for jsonParam in jsonNameValues:
                jsonTmp = []
                jsonTmp.append(jsonParam[JSON_NAME])
                jsonTmp.append(jsonParam[JSON_VALUE])
                jsonParamList.append(jsonTmp)
        except:
            jsonTmp = []
            jsonTmp.append(jsonParam)
            jsonTmp.append("")
            jsonParamList.append(jsonTmp)
        return jsonParamList

    def bodyParam(self, bodyParams):
        bodyParamList = []
        bodyParams = bodyParams.split('&')

        for bodyParam in bodyParams:
            bodyParam = bodyParam.split('=', 1) 
            bodyParamList.append(bodyParam)
  
        return bodyParamList

    def siteMapCreate(self, jsonLoad):
        siteMapLists = []

        for requestInfo in jsonLoad:
            tmpDic = {
                "location" : "",
                "url" : "",
                "QueryParam" : "",
                "BodyParam" : "",
                "JsonParam" : "",
                "Path" : "",
                "status" : ""
            }
            if "Comment" in requestInfo["Proxy"]:
                tmpDic["location"] = requestInfo["Proxy"]["Comment"]

            if "URL" in requestInfo["Request"]:
                tmpDic["url"] = requestInfo["Request"]["URL"]

            if "Query" in requestInfo["Request"] :
                tmpDic['QueryParam'] = self.queryParamList(requestInfo["Request"]["Query"])

            if "Path" in requestInfo["Request"]:
                tmpDic['Path'] = requestInfo["Request"]["Path"]

            if "Body" in requestInfo["Request"]:
                if len(requestInfo["Request"]["Body"]) != 0:
                    if "ContentType" in requestInfo["Request"]:

                        bodyParamList =[]
                        if "multipart" in requestInfo["Request"]["ContentType"]:
                            bodyParamList = self.multipart(requestInfo)
                        elif "json" in requestInfo["Request"]["ContentType"]:
                            tmpDic["JsonParam"] = self.jsonParam(requestInfo["Request"]["Body"])
                        else:
                            bodyParamList = self.bodyParam(requestInfo["Request"]["Body"])
                        tmpDic['BodyParam'] = bodyParamList

            siteMapLists.append(tmpDic)
        siteMapLists = self.duplicateCheck(siteMapLists)
        return siteMapLists
