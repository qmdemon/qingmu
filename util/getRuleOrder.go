package util

import (
	"bufio"
	"io"
	"log"
	"os"
	"strings"
)

// 获取yaml poc 执行顺序
func RuleKeys(filename string) map[string][]string {

	rulemap := make(map[string][]string) //生成一个用于保存执行流程的map

	var rulekeys []string //用于保存rule执行流程
	var output []string   // 用于保存output 执行流程
	var a string          // 用于保存当前rule

	file, err := os.Open(filename)
	if err != nil {
		log.Fatalln(filename, "打开错误")
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	var rulestart = false

	var outstart = false

	for {

		str, err := reader.ReadString('\n') //读取到一个换行符就结束
		//str = strings.TrimSpace(str)
		if err == io.EOF { //io.EOF 表示文件的结尾
			break

		}

		if strings.Index(str, "rules:") == 0 {
			rulestart = true
		}

		if strings.Index(str, "expression:") == 0 {
			rulestart = false
		}

		if rulestart {

			if strings.Index(str, "  ") == 0 && str[2] != 32 {
				output = nil
				str = strings.TrimSpace(str)
				a = str[:len(str)-1]
				rulekeys = append(rulekeys, a)
				outstart = false

			}

			if strings.Index(str, "    output:") == 0 {
				outstart = true

			}
			if outstart {
				if strings.Index(str, "      ") == 0 && str[6] != 32 {
					b := strings.Split(strings.TrimSpace(str), ":")
					output = append(output, b[0])
				}
			}

			rulemap[a] = output

		}

	}

	rulemap["rules"] = rulekeys

	return rulemap

}
