![](https://socialify.git.ci/nu1r/GolangStruts2/image?description=1&font=Raleway&language=1&logo=https%3A%2F%2Fs1.ax1x.com%2F2022%2F09%2F12%2FvXqOUI.jpg&name=1&owner=1&pattern=Signal&theme=Light)

用Golang重写[Struts2-Scan](https://github.com/HatBoy/Struts2-Scan)项目。

工具参数说明
```
Usage of main.exe:
  -u url
      you target, example: https://192.168.1.1
  -c command
      you want execute command, example: "whoami"
  -n name
      漏洞名，可选S2-001, S2-003, S2-005, S2-007, S2-008, S2-009, S2-012, S2-013, S2-015, S2-016, S2-019,
                S2-029, S2-032, S2-033, S2-037, S2-045, S2-046, S2-048, S2-052, S2-053, S2-devMode, S2-057,allPoc(除了s2-052)
                (单独使用POC | EXP 例: S2-001 | s2-001_Cmd | s2-001_WebPath)
  -d data
          POST , 需要使用的payload使用{exp}填充, 如: name=test&passwd={exp}
  -t Type
      指定contentType头
```