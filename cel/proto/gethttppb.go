package proto

import (
	"github.com/valyala/fasthttp"
	"log"
	"qingmu/httpclient"
	"regexp"
	"strings"
)

func GetResponse(resp httpclient.Response, req *fasthttp.Request) (*Response, error) {
	var pbresp Response

	pbresp.Raw = []byte(resp.Resp.String())

	pbresp.Status = int32(resp.Resp.StatusCode())

	pbresp.RawHeader = resp.Resp.Header.Header()
	pbresp.Body = resp.Resp.Body()
	//pbresp.BodyString = resp.Resp.Body()
	pbresp.ContentType = string(resp.Resp.Header.ContentType())

	pbresp.BodyString = httpclient.GetResponseBodyString(pbresp.Body, pbresp.Headers["Content-Encoding"])

	pbresp.Latency = resp.Latency

	// title 正则表达式
	r, _ := regexp.Compile(`<title>(.*?)</title>`)
	t := r.FindStringSubmatch(pbresp.BodyString)

	if len(t) == 0 {
		pbresp.TitleString = ""
		pbresp.Title = nil
	} else {
		pbresp.TitleString = t[1]
		pbresp.Title = []byte(t[1])
	}

	pbresp.Url = GetUrlType(req.URI())

	respheaders, err := httpclient.GetResponseHeaders(resp.Resp.String())
	if err != nil {
		log.Println("获取responseheaders错误", err)
		return &pbresp, err
	}
	pbresp.Headers = make(map[string]string)

	for k, v := range respheaders {
		pbresp.Headers[k] = strings.Join(v, "，")
		//fmt.Println(k, v)
	}

	return &pbresp, nil
}

func GetUrlType(uri *fasthttp.URI) *UrlType {
	nu := &UrlType{}
	nu.Scheme = string(uri.Scheme())
	//nu.Domain = string(uri.Host())
	nu.Host = string(uri.Host())
	//nu.Port = req.URI().Port()
	nu.Path = string(uri.Path())
	nu.Query = string(uri.QueryString())

	host := strings.Split(nu.Host, ":")

	if len(host) == 1 {
		if nu.Scheme == "http" {
			nu.Port = "80"
		} else {
			nu.Port = "443"
		}
		nu.Domain = nu.Host
	} else {
		nu.Port = host[1]
		nu.Domain = host[0]
	}

	fragment := strings.Split(uri.String(), "#")

	if len(fragment) == 1 {
		nu.Fragment = ""
	} else {
		nu.Fragment = fragment[1]
	}
	return nu
}

func GetRequest(req *fasthttp.Request) (*Request, error) {

	var pbreq Request

	pbreq.Raw = []byte(req.String())

	pbreq.Url = GetUrlType(req.URI())
	pbreq.Method = string(req.Header.Method())

	pbreq.ContentType = string(req.Header.ContentType())

	pbreq.RawHeader = req.Header.Header()

	pbreq.Body = req.Body()

	reqheaders, err := httpclient.GetRequestHeaders(req.String())
	if err != nil {
		log.Println("获取responseheaders错误", err)
		return &pbreq, err
	}
	pbreq.Headers = make(map[string]string)

	for k, v := range reqheaders {
		pbreq.Headers[k] = strings.Join(v, "，")
		//fmt.Println(k, v)
	}

	return &pbreq, nil
}
