package proto

import (
	"bytes"
	"github.com/valyala/fasthttp"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"qingmu/httpclient"
	"strings"
)

func GetResponse(resp *fasthttp.Response, req *http.Request) (*Response, error) {
	var pbresp Response

	pbresp.Status = int32(resp.StatusCode())
	pbresp.ContentType = string(resp.Header.ContentType())
	pbresp.Body = resp.Body()
	respheaders, err := httpclient.GetResponseHeaders(resp.String())
	if err != nil {
		log.Println("获取responseheaders错误", err)
		return &pbresp, err
	}
	pbresp.Headers = make(map[string]string)

	for k, v := range respheaders {
		pbresp.Headers[k] = strings.Join(v, "，")
		//fmt.Println(k, v)
	}
	pbresp.Url = GetUrlType(req.URL)

	return &pbresp, nil
}

func GetUrlType(u *url.URL) *UrlType {
	nu := &UrlType{}
	nu.Scheme = u.Scheme
	nu.Domain = u.Hostname()
	nu.Host = u.Host
	nu.Port = u.Port()
	nu.Path = u.EscapedPath()
	nu.Query = u.RawQuery
	nu.Fragment = u.Fragment
	return nu
}

func GetRequest(oReq *http.Request) (*Request, error) {
	req := &Request{}
	req.Method = oReq.Method
	req.Url = GetUrlType(oReq.URL)
	header := make(map[string]string)
	for k := range oReq.Header {
		header[k] = oReq.Header.Get(k)
	}
	req.Headers = header
	req.ContentType = oReq.Header.Get("Content-Type")
	if oReq.Body == nil || oReq.Body == http.NoBody {
	} else {
		data, err := ioutil.ReadAll(oReq.Body)
		if err != nil {
			return nil, err
		}
		req.Body = data
		oReq.Body = ioutil.NopCloser(bytes.NewBuffer(data))
	}
	return req, nil
}
