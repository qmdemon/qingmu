package main

import (
	"qingmu/report"
	"sync"
)

func main() {
	var wg sync.WaitGroup

	rep := report.Report{
		Title: "测试输出",
	}

	rep.Set("1", "第一次请求", "第一次响应")
	rep.Set("2", "第二次请求", "第二次响应")

	//do := make(chan report.Report)
	go report.OutPutDocx(rep, &wg)
	wg.Add(1)
	wg.Wait()

}
