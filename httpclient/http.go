package httpclient

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"qingmu/global"
	"qingmu/pocstruct"
	"qingmu/report"
	"strings"
	"time"
)

// 用于保存当前请求以及响应
type Response struct {
	Resp    *fasthttp.Response
	Req     *fasthttp.Request
	Latency int32 //请求响应时间
}

func HttpRequest(addr string, pocRequest pocstruct.Request, Expression string, Description string, rep *report.Report) (r Response, err error) {

	addr = strings.TrimSpace(addr)

	url := addr + pocRequest.Path

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

	// 设置fasthttp代理
	//client.Dial = FasthttpHTTPDialer("127.0.0.1:8080")
	if global.Proxy != "" {
		if strings.HasPrefix(global.Proxy, "https://") {
			p := strings.Split(global.Proxy, "://")
			//client.Dial = FasthttpHTTPDialer(p[1])
			client.Dial = fasthttpproxy.FasthttpHTTPDialer(p[1])
		} else if strings.HasPrefix(global.Proxy, "http://") {
			p := strings.Split(global.Proxy, "://")
			client.Dial = fasthttpproxy.FasthttpHTTPDialer(p[1])
		} else if strings.HasPrefix(global.Proxy, "sock") {
			client.Dial = fasthttpproxy.FasthttpSocksDialer(global.Proxy)
		} else {
			log.Fatalln("代理格式设置错误")
		}
	}

	// 判断是否跟随重定向
	if pocRequest.FollowRedirects {

		//fmt.Println("默认设置?")// 默认设置为false
		// 请求开始时间
		time_start := time.Now()
		err = client.DoRedirects(req, resp, 5) // 设置最大重定向为5

		r.Latency = int32(time.Since(time_start).Milliseconds()) // 计算请求结束时间

		log.Println("请求失败:", err.Error())

		r.Resp = resp
		r.Req = req

		return r, err

	} else {
		// 请求开始时间
		time_start := time.Now()
		err = client.Do(req, resp)
		r.Latency = int32(time.Since(time_start).Milliseconds()) // 计算请求结束时间
		if err != nil {
			log.Println("请求失败:", url, err.Error())
			r.Resp = resp
			r.Req = req
			return r, err
		}
	}
	//fmt.Println(resp.StatusCode())
	rep.SetVulInfo(Description, req.String(), resp.String(), Expression)
	if global.IsShowPath {
		fmt.Println(pocRequest.Method, url)
	}
	if global.IsShowRequest {
		fmt.Println(req.String())
	}
	if global.IsShowResponse {
		fmt.Println(resp.String())
	}
	r.Resp = resp
	r.Req = req
	return r, nil

}

func GetResponseHeaders(fasthttpresp string) (http.Header, error) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader([]byte(fasthttpresp))), nil)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

	return resp.Header, err
}

func GetRequestHeaders(fasthttpreq string) (http.Header, error) {
	resp, err := http.ReadRequest(bufio.NewReader(bytes.NewReader([]byte(fasthttpreq))))
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

	return resp.Header, err
}

func GetResponseBodyString(body []byte, ce string) string {
	if ce == "gzip" {
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return string(body)
		}

		body, _ = ioutil.ReadAll(reader)

		return string(body)

	} else {
		return string(body)
	}
}

// http代理
func FasthttpHTTPDialer(proxyAddr string) fasthttp.DialFunc {
	return func(addr string) (net.Conn, error) {
		conn, err := fasthttp.Dial(proxyAddr)
		if err != nil {
			return nil, err
		}

		req := "CONNECT " + addr + " HTTP/1.1\r\n"
		// req += "Proxy-Authorization: xxx\r\n"
		req += "\r\n"

		if _, err := conn.Write([]byte(req)); err != nil {
			return nil, err
		}

		res := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseResponse(res)

		res.SkipBody = true

		if err := res.Read(bufio.NewReader(conn)); err != nil {
			conn.Close()
			return nil, err
		}
		if res.Header.StatusCode() != 200 {
			conn.Close()
			return nil, fmt.Errorf("could not connect to proxy")
		}
		return conn, nil
	}
}
