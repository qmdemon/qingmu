package main

import (
	"fmt"
	"github.com/valyala/fasthttp"
	"time"
)

func main() {

	url := `https://httpbin.org/post?key=123`

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req) // 用完需要释放资源

	// 默认是application/x-www-form-urlencoded
	req.Header.SetContentType("application/json")
	req.Header.SetMethod("POST")
	req.Header.SetUserAgent("fasthttp,qm")
	req.Header.Set("token", "123456")
	req.Header.SetContentType("")
	//req.Header.Set("User-agent", "google")

	req.SetRequestURI(url)

	req.SetTimeout(time.Second)
	requestBody := []byte(`{"request":"test"}`)
	req.SetBody(requestBody)

	//urltype := myproto.GetUrlType(req)

	fmt.Println(urltype.Host)

}
