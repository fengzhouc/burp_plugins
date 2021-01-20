功能介绍

主要是收集domain、path、param、js等信息字典

2021.1.20修改
重定义收集的信息
eg：http://xxx.com/api/v1/test?param1=1
dirDicts /api/v1/test,api,v1,test
fileDicts /api/v1/test,test(会根据后缀分类)
paramDicts param,api,v1,test(无后缀的)
domainDict


收集的数据还没有去重的，可以使用pydictor工具去重、合并数据