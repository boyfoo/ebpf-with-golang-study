### 查看命令的符号表

如`bash`命令

查看命令位置 `which bash`

查看命令对应某位置的符号表 `nm -D /usr/bin/bash | grep readline`

目标使用 readline 查看用户输入了什么

将`cmd/sys/main.go` 内执行切为`sys.LoadBash()`

### 查看go函数返回

go函数需要有不同返回的可能，如判断，不然写死了查不到这个函数

将`cmd/sys/main.go` 内执行切为`sys.LoadGolangFunc()`

`go build -o http cmd/http/main.go`

查看`nm http | grep main`

运行 `./http`

`go run cmd/sys/main.go`

`curl "http://127.0.0.1:8899?id=12"`


> 截止v1.0