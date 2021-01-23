#功能介绍

主要是收集domain、path、param、js等信息字典

2021.1.20修改

重定义收集的信息

eg：http://xxx.dd.com/api/v1/test?param1=1

dirDicts /api/v1/test,api,v1,test

fileDicts /api/v1/test,test(会根据后缀分类)

paramDicts param,api,v1,test(无后缀的)

domainDict xxx


#数据处理
收集的数据还没有去重的，可以使用pydictor工具去重、合并数据

##合并数据(多个文件放在同一个目录)

`python pydictor.py -tool combiner /my/dict/dirpath -o comb.txt`

##去重数据

`python pydictor.py -tool uniqifer comb.txt -o uniq.txt`

##去重并合并数据

`python pydictor.py -tool uniqbiner /my/dict/dirpath -ou uniq.txt`

##词频统计(去重前的数据来统计)

修改 lib/data/data.py 中 counter_split 变量指定的分隔符 ( 默认 "\n" )，也可以统计其它字符分隔的字典词频.

`python pydictor.py -tool counter vs comb.txt 1000`