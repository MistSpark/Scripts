package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	// Example URL: http://example.com/files/avatars/test.php
	url := ""
	for {
		resp, err := http.Get(url)
		if err != nil {
			fmt.Println("Error: ", err)
		} else {
			fmt.Println("Response: ", resp.Status)
			io.Copy(os.Stdout, resp.Body)
			fmt.Println()
		}
		time.Sleep(time.Second * 0)
	}
}
