package main

import (
	"fmt"
	"net/http"
)

func MyRes(r *http.Request) string {
	s := r.URL.Query().Get("id")
	if s != "" {
		return fmt.Sprintf("query by id:%s", s)
	}
	return fmt.Sprintf("no %s", "query")
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 这里可以写一些业务逻辑
		w.Write([]byte(MyRes(r)))
	})
	fmt.Println("启动http")
	http.ListenAndServe(":8899", nil)
}
