package main

import (
	"fmt"
	"io"
	"net"
	"time"
)

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:18999")
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				t := c.(*net.TCPConn)
				_ = t.SetLinger(0)
				_ = t.Close() // abrupt RST, no bytes written
			}(c)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	c, err := net.Dial("tcp", "127.0.0.1:18999")
	if err != nil {
		panic(err)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	n, cerr := io.Copy(io.Discard, c)
	fmt.Printf("RST-close peer: io.Copy bytes=%d err=%v (nil err => recorded allowed=true)\n", n, cerr)
	c.Close()
}
