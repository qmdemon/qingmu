package httpclient

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"github.com/valyala/fasthttp"
	"log"
	"net/http"
	"qingmu/pocstruct"
	"qingmu/report"
	"strings"
)

func HttpRequest(addr string, pocRequest *pocstruct.Request, Expression string, rep *report.Report) (*fasthttp.Response, error) {
	addr = strings.TrimSpace(addr)

	url := addr + pocRequest.Path

	//fmt.Println(url)

	req := fasthttp.AcquireRequest()
	//defer fasthttp.ReleaseRequest(req) // 用完需要释放资源

	req.Header.SetMethod(pocRequest.Method)

	if pocRequest.Headers != nil {
		for k, v := range pocRequest.Headers {
			req.Header.Set(k, v)
		}
	}
	req.SetRequestURI(url)
	//req.SetTimeout(time.Second)

	if pocRequest.Body != "" {
		req.SetBody([]byte(pocRequest.Body))
	}

	resp := fasthttp.AcquireResponse()
	//defer fasthttp.ReleaseResponse(resp) // 用完需要释放资源，不能在此释放资源，否则会导致resp无法传出

	client := fasthttp.Client{
		TLSConfig:              &tls.Config{InsecureSkipVerify: true},
		DisablePathNormalizing: true, // 设置不对url进行处理
	} //创建一个clien，并不进行tls证书验证

	if err := client.Do(req, resp); err != nil {
		log.Println("请求失败:", err.Error())
		return resp, err
	}
	//fmt.Println(resp.StatusCode())
	rep.Set(req.String(), resp.String(), Expression)

	return resp, nil

}

func GetResponseHeaders(fasthttpresp string) (http.Header, error) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader([]byte(fasthttpresp))), nil)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

	return resp.Header, err
}

func NetHttpReq(addr string, pocRequest *pocstruct.Request) (*http.Request, error) {

	addr = strings.TrimSpace(addr)

	url := addr + pocRequest.Path
	req, err := http.NewRequest(pocRequest.Method, url, strings.NewReader(pocRequest.Body))
	if err != nil {
		log.Println("生成net/http/req错误", err)
		return nil, err
	}

	if pocRequest.Headers != nil {
		for k, v := range pocRequest.Headers {
			req.Header.Set(k, v)
		}
	}

	return req, nil

}
