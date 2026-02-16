package server

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	monitoring "github.com/komari-monitor/komari-agent/monitoring/unit"
)

type ProbeConfig struct {
	Port int
	Path string
}

func StartProbeServer(cfg ProbeConfig) {
	if cfg.Port == 0 {
		return
	}
	if cfg.Path == "" {
		cfg.Path = "/probetest"
	}

	mux := http.NewServeMux()
	base := cfg.Path

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?><root></root>"))
	})

	// ===== HTML 入口页面 =====
	mux.HandleFunc(base, func(w http.ResponseWriter, r *http.Request) {
		//http.ServeFile(w, r, "server/probetest.html") //debug模式 二进制静态文件 下面把静态文件编译进二进制

		data, err := probeFS.ReadFile("probetest.html")
		if err != nil {
			http.Error(w, "not found", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write(data)
	})

	// ===== basic 接口 =====
	mux.HandleFunc(base+"/basic", func(w http.ResponseWriter, r *http.Request) {

		// ===== 获取数据（全部来自 monitoring/unit） =====

		cpu := monitoring.Cpu()
		load := monitoring.Load()
		ram := monitoring.Ram()
		swap := monitoring.Swap()
		disk := monitoring.Disk()

		upTotal, downTotal, upSpeed, downSpeed, _ := monitoring.NetworkSpeed()
		ipv4, ipv6, _ := monitoring.GetIPAddress()
		tcpCount, udpCount, _ := monitoring.ConnectionsCount()

		uptime, _ := monitoring.Uptime()

		// ===== 构造兼容 HTML 的 JSON =====

		resp := map[string]interface{}{
			"cpu":            cpu.CPUUsage,
			"process_count": monitoring.ProcessCount(),
			"mem_total":      ram.Total,
			"mem_used":       ram.Used,
			"swap_total":     swap.Total,
			"swap_used":      swap.Used,
			"disk_total":     disk.Total,
			"disk_used":      disk.Used,
			"load1":         load.Load1,
			"load5":         load.Load5,
			"load15":        load.Load15,
			"net_up_speed":   upSpeed,
			"net_down_speed": downSpeed,
			"net_up_total":   upTotal,
			"net_down_total": downTotal,
			"uptime":         uptime,
			"os":             monitoring.OSName(),
			"kernel":         monitoring.KernelVersion(),
			"ipv4":           ipv4,
			"ipv6":           ipv6,
			"tcp_count":           tcpCount,
			"udp_count":           udpCount,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// ===== ping =====
	mux.HandleFunc(base+"/empty", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})

	// ===== download =====
	mux.HandleFunc(base+"/garbage", func(w http.ResponseWriter, r *http.Request) {

		chunks := 4
		if v := r.URL.Query().Get("ckSize"); v != "" {
			if i, err := strconv.Atoi(v); err == nil {
				if i > 64 {
					i = 64 // 限制最大块数，避免滥用
				}
				chunks = i
			}
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")

		for i := 0; i < chunks; i++ {
			data := make([]byte, 1024*1024)
			rand.Read(data)
			_, err := w.Write(data)
			if err != nil {
				return
			}
		}
	})

	addr := fmt.Sprintf(":%d", cfg.Port)

	go func() {
		s := &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		fmt.Println("Probe server running at", addr+base)
		s.ListenAndServe()
	}()
}