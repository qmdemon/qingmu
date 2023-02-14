package main

import (
	"fmt"
	"log"
	"qingmu/pocstruct"
)

func main() {

	poc, err := pocstruct.LoadPoc("httpbin-test.yml")
	if err != nil {
		log.Fatalln("解析yml错误：", err)
	}

	syncmap := poc.Rules["r0"].OutPut

	syncmap.Range(func(k, v interface{}) bool {
		fmt.Println("iterate:", k, v)
		return true
	})

	//fmt.Println(a)

}
