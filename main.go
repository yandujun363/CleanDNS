package main

import (
	"fmt"
	"os"
)

func main() {
	// 检查配置文件参数
	if len(os.Args) < 2 {
		fmt.Println("使用方法: cleandns <配置文件路径>")
		fmt.Println("示例: cleandns config.json")
		os.Exit(1)
	}

	configFile := os.Args[1]

	// 创建DNS代理
	proxy, err := NewDNSProxy(configFile)
	if err != nil {
		fmt.Printf("创建DNS代理失败: %v\n", err)
		os.Exit(1)
	}

	// 启动DNS代理
	if err := proxy.Start(); err != nil {
		fmt.Printf("启动失败: %v\n", err)
		os.Exit(1)
	}
}