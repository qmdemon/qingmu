package main

import (
	"fmt"
	"log"
	"qingmu/cel"
	"qingmu/poc"
)

func main() {

	filename := "test/httpbin-test.yml"

	var pocs []*poc.Poc

	for i := 0; i < 100; i++ {
		poc, err := poc.LoadPoc(filename)
		if err != nil {
			log.Fatalln("解析yml错误：", err)
		}

		pocs = append(pocs, poc)

	}

	//fmt.Println(poc.Rules["r2"].Request.Path)

	addr := "https://httpbin.org"

	pocresult := make(chan bool)

	for _, p := range pocs {
		go cel.EvalPoc(addr, p, filename, pocresult)

	}

	for i := 0; i < 100; i++ {
		success := <-pocresult
		//fmt.Println(success)
		if success {
			fmt.Println(addr, pocs[i].Name, "漏洞存在")
		} else {
			fmt.Println(addr, pocs[i].Name, "漏洞不存在")
		}
	}

}
