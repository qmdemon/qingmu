package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"qingmu/cel"
	"qingmu/pocstruct"
	"qingmu/utils"
)

var (
	target   string
	linkfile string
	pocfile  string
	poctype  string
	tnum     int
	pnum     int
)

func Init() {
	flag.StringVar(&target, "target", "", "扫描目标")
	flag.StringVar(&linkfile, "linkfile", "", "目标地址文件")
	flag.StringVar(&pocfile, "pocfile", "", "poc文件")
	flag.StringVar(&poctype, "poctype", "/", "poc类型")
	flag.IntVar(&tnum, "tnum", 10, "扫描target协(线)程数量")
	flag.IntVar(&pnum, "pnum", 10, "扫描poc协(线)程数量")

	flag.Parse()
}

func main() {

	Init()
	var links []string
	var poclist []string

	switch {
	case target != "":

		if pocfile != "" { // 一对一

			links = append(links, target)
			poclist = append(poclist, pocfile)

		} else if poctype != "" { // 一对多

			//err := error()

			poclist = utils.Getfilepath(poctype)

			// 要传递多个target，使一个target匹配一个poc，否则只会执行第一个poc
			for i := 0; i < len(poclist); i++ {
				links = append(links, target)
			}

		} else {
			fmt.Println("pocfile/poctype 不能为空")
			os.Exit(0)
		}

	case linkfile != "":

		if pocfile != "" { //多对一
			links = utils.Getllinks(linkfile)
			for i := 0; i < len(links); i++ {

				poclist = append(poclist, pocfile)
			}

		} else if poctype != "" { //多对多
			ls := utils.Getllinks(linkfile)
			pt := utils.Getfilepath(poctype)

			for i := 0; i < len(ls); i++ {
				for j := 0; j < len(pt); j++ {
					links = append(links, ls[i])
					poclist = append(poclist, pt[j])
				}
			}

		} else {
			fmt.Println("pocfile/poctype 不能为空")
			os.Exit(0)
		}

	default:
		fmt.Println("target/linkfile 不能为空")
	}

	pocresult := make(chan string)
	targets := make(chan string, tnum)
	pocs := make(chan string, pnum)

	// 添加地址扫描队列
	go func() {
		for _, link := range links {
			targets <- link
		}
	}()

	// 添加poc扫描队列
	go func() {
		for _, poc := range poclist {
			pocs <- poc
		}
	}()

	// 执行poc
	for i := 0; i < cap(targets); i++ {
		for j := 0; j < cap(pocs); j++ {
			go runpoc(targets, pocresult, pocs)
		}
	}

	// 输出结果
	for i := 0; i < len(links); i++ {
		result := <-pocresult
		fmt.Println(result)
	}

	close(pocresult)
	close(targets)
	close(pocs)

}

func runpoc(targets chan string, pocresult chan string, pocs chan string) {

	for t := range targets {
		for p := range pocs {

			//fmt.Println(p)
			poc, err := pocstruct.LoadPoc(p)
			if err != nil {
				log.Fatalln("解析yml错误：", err)
			}
			success := cel.EvalPoc(t, poc, p)

			if success {
				pocresult <- fmt.Sprintf("%s 存在 %s 漏洞", t, poc.Name)
			} else {
				pocresult <- fmt.Sprintf("%s 不存在 %s 漏洞", t, poc.Name)
			}
		}

	}
}
