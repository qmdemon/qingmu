package main

import (
	"fmt"
	"qingmu/utils"
)

func main() {

	filename := "test/httpbin-test.yml"

	a := utils.RuleKeys(filename)

	fmt.Println(a)

}
