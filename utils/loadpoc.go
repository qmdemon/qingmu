package utils

import (
	"bufio"
	"io"
	"io/ioutil"
	"log"
	"os"
	"qingmu/pocstruct"
	"strings"
)

// 读取链接文件，生成链接数组数组
func Getllinks(linkfile string) []string {

	var links []string

	file, err := os.Open(linkfile)
	if err != nil {
		log.Fatalln(linkfile, "打开错误")
	}
	defer file.Close()
	reader := bufio.NewReader(file)

	for {

		str, err := reader.ReadString('\n') //读取到一个换行符就结束
		//str = strings.TrimSpace(str)
		if err == io.EOF { //io.EOF 表示文件的结尾
			break
		}

		str = strings.TrimSpace(str)
		links = append(links, str)

	}
	return links
}

//
func Getpoclist(poctype string) map[string]*pocstruct.Poc {
	//var pocmaplist []map[string]*pocstruct.Poc
	pocmap := make(map[string]*pocstruct.Poc)
	files := Getfilepath(poctype)

	for _, f := range files {
		poc, err := pocstruct.LoadPoc(f)
		if err != nil {
			log.Printf("解析%v错误：%v \n", f, err)
			continue
		}

		pocmap[f] = poc
		//pocmaplist = append(pocmaplist,)
	}

	return pocmap
}

// 获取poc目录下的所有文件
func Getfilepath(poctype string) []string {

	poctype = "poc/" + strings.TrimSuffix(poctype, string(os.PathSeparator))
	//fmt.Println(poctype)

	infos, err := ioutil.ReadDir(poctype)
	if err != nil {
		log.Fatalln("读取目录错误", err)
	}

	paths := make([]string, 0, len(infos))
	for _, info := range infos {
		path := poctype + string(os.PathSeparator) + info.Name()
		//fmt.Println(path)
		if info.IsDir() {
			tmp := Getfilepath(path)

			paths = append(paths, tmp...)
			continue
		}
		paths = append(paths, path)
	}
	return paths

}
