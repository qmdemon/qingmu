package main

import (
	"fmt"
	"qingmu/util"
)

func main() {

	filename := "test/httpbin-test.yml"

	a := util.RuleKeys(filename)

	fmt.Println(a)

}
