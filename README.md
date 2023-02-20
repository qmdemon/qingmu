# qingmu

基于xray poc的漏洞扫描框架

本项目是为了学习go语言而编写，目标是希望实现xray 主动扫描功能以及被动扫描功能

已完成第一阶段目标，使用xray poc进行漏洞漏洞扫描，并导出docx报告

使用ceye.io 作为反连测试平台

## 基本使用

对单独目标进行扫描

    ./main -target http://httpbin.org -pocfile poc/test/httpbin-test.yml        一个poc
    ./main -target http://httpbin.org -poctype test                             一类poc  会使用poc/test 目录下的所有poc

对多个目标进行扫描

    ./main -linkfile link.txt -pocfile poc/test/httpbin-test.yml 
    ./main -linkfile link.txt -poctype test

## 参数
```
  -ceyeapi string
        ceyeapi
  -ceyedomain string
        ceyedomain
  -linkfile string
        目标地址文件
  -pnum int
        扫描poc协(线)程数量 (default 10)
  -pocfile string
        poc文件
  -poctype string
        poc类型 (default "/")
  -proxy string
        设置请求代理
  -showpath
        是否显示请求路径
  -showreq
        是否显示请求数据
  -showresp
        是否显示请求方法
  -target string
        扫描目标
  -tnum int
        扫描目标地址协(线)程数量 (default 10)
```

showpath，showresp，showreq 参数一般用于测试poc



## 学习文章：
https://xz.aliyun.com/t/11127

## 学习cel 基础：
https://codelabs.developers.google.com/codelabs/cel-go/#0

## 参考项目：
https://github.com/jweny/pocassist

https://github.com/jjf012/gopoc

https://github.com/yuuuuu422/Gopo
