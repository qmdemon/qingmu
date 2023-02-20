package utils

import (
	"bytes"
	"fmt"
	"github.com/valyala/fasthttp"
	"log"
	"math/rand"
	"net/url"
	"qingmu/cel/proto"
	"qingmu/global"
	"strings"
	"time"
)

func NewReverse() *proto.Reverse {
	flag := RandLetters(8)
	if global.CeyeDomain == "" {
		return &proto.Reverse{}
	}
	urlStr := fmt.Sprintf("http://%s.%s", flag, global.CeyeDomain)
	u, _ := url.Parse(urlStr)
	return &proto.Reverse{
		Flag:               flag,
		Url:                proto.GetUrlType(u),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}

func ReverseCheck(r *proto.Reverse, timeout int64) bool {
	if global.CeyeApi == "" || r.Domain == "" {
		return false
	}

	// 延迟多少秒
	time.Sleep(time.Second * time.Duration(timeout))
	//请求转化为小写
	sub := strings.ToLower(r.Flag)
	url := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s", global.CeyeApi, sub)
	if getceye(url) {
		return true
	} else {
		url = fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=http&filter=%s", global.CeyeApi, r.Flag)
		if getceye(url) {
			return true
		}
	}
	return false
}

func getceye(url string) bool {
	status, resp, err := fasthttp.Get(nil, url)
	if err != nil || status != fasthttp.StatusOK {
		log.Println("ceye.io请求错误,状态码：", status, "错误 ", err)
		return false
	}
	if !bytes.Contains(resp, []byte(`"data": []`)) { // api返回结果不为空
		return true
	}

	return false
}

const letterBytes = "abcdefghijklmnopqrstuvwxyz"
const letterNumberBytes = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const lowletterNumberBytes = "0123456789abcdefghijklmnopqrstuvwxyz"

func RandFromChoices(n int, choices string) string {

	randSource := rand.New(rand.NewSource(time.Now().Unix()))
	const (
		letterIdxBits = 6                    // 6 bits to represent a letter index
		letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
		letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	)
	randBytes := make([]byte, n)
	for i, cache, remain := n-1, randSource.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSource.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			randBytes[i] = choices[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(randBytes)

}

// RandLetters 随机小写字母
func RandLetters(n int) string {
	return RandFromChoices(n, letterBytes)
}

// RandLetterNumbers 随机大小写字母和数字
func RandLetterNumbers(n int) string {
	return RandFromChoices(n, letterNumberBytes)
}

// RandLowLetterNumber 随机小写字母和数字
func RandLowLetterNumber(n int) string {
	return RandFromChoices(n, lowletterNumberBytes)
}
