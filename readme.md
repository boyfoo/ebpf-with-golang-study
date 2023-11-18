### 查看命令的符号表

如`bash`命令

查看命令位置 `which bash`

查看命令对应某位置的符号表 `nm -D /usr/bin/bash | grep readline`

目标使用 readline 查看用户输入了什么

