package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spf13/pflag"
)

var (
	logger = log.New(os.Stdout, "[android_bounty_hunter] ", log.Ldate|log.Ltime)
	wg     sync.WaitGroup
)

type Config struct {
	apkPath    string
	package    string
	outputDir  string
	deviceDir  string
	mobsf      bool
	traffic    bool
	verbose    bool
	threads    int
}

func main() {
	// Command-line flags
	config := Config{}
	pflag.StringVarP(&config.apkPath, "apk", "a", "", "Path to APK file (required)")
	pflag.StringVarP(&config.package, "package", "p", "", "App package name (required)")
	pflag.StringVarP(&config.outputDir, "output", "o", "", "Output directory (default: <package>_output)")
	pflag.StringVarP(&config.deviceDir, "device-dir", "d", "", "Device data directory (default: /data/data/<package>)")
	pflag.BoolVarP(&config.mobsf, "mobsf", "m", true, "Run MobSF analysis")
	pflag.BoolVarP(&config.traffic, "traffic", "t", false, "Capture traffic with mitmproxy")
	pflag.BoolVarP(&config.verbose, "verbose", "v", false, "Verbose output")
	pflag.IntVarP(&config.threads, "threads", "n", 5, "Number of parsing threads")
	pflag.Parse()

	// Validation
	if config.apkPath == "" || config.package == "" {
		fmt.Println("Usage: android_bounty_hunter -a <apk> -p <package> [options]")
		pflag.PrintDefaults()
		os.Exit(1)
	}
	if config.outputDir == "" {
		config.outputDir = fmt.Sprintf("%s_output", config.package)
	}
	if config.deviceDir == "" {
		config.deviceDir = fmt.Sprintf("/data/data/%s", config.package)
	}

	// Setup
	if err := os.MkdirAll(config.outputDir, 0755); err != nil {
		logger.Fatalf("Failed to create output dir: %v", err)
	}
	logFile, err := os.Create(filepath.Join(config.outputDir, "hunter.log"))
	if err != nil {
		logger.Fatalf("Failed to create log file: %v", err)
	}
	defer logFile.Close()
	logger.SetOutput(logFile)
	if config.verbose {
		logger.SetOutput(io.MultiWriter(os.Stdout, logFile))
	}

	// Execute pipeline
	logger.Println("Starting analysis...")
	extractData(config)
	parseData(config)
	logger.Println("Analysis completed. Results in", config.outputDir)
}

// extractData handles APK decompilation, MobSF, and device data extraction
func extractData(config Config) {
	// Decompile with JADX
	logger.Println("Decompiling APK with JADX...")
	cmd := exec.Command("jadx", "-d", filepath.Join(config.outputDir, "decompiled"), config.apkPath)
	if err := cmd.Run(); err != nil {
		logger.Printf("JADX decompilation failed: %v", err)
	} else {
		logger.Println("Decompilation completed")
	}

	// Run MobSF if enabled
	if config.mobsf {
		logger.Println("Running MobSF analysis...")
		mobsfCmd := exec.Command("docker", "run", "-it", "--rm",
			"-v", fmt.Sprintf("%s:/home/mobsf/apk.apk", config.apkPath),
			"opensecurity/mobile-security-framework-mobsf",
			"mobsfscan", "/home/mobsf/apk.apk")
		mobsfOut, err := os.Create(filepath.Join(config.outputDir, "mobsf_report.txt"))
		if err != nil {
			logger.Printf("Failed to create MobSF report file: %v", err)
		} else {
			mobsfCmd.Stdout = mobsfOut
			mobsfCmd.Stderr = mobsfOut
			if err := mobsfCmd.Run(); err != nil {
				logger.Printf("MobSF failed: %v", err)
			} else {
				logger.Println("MobSF analysis completed")
			}
			mobsfOut.Close()
		}
	}

	// Capture traffic if enabled
	if config.traffic {
		logger.Println("Starting traffic capture with mitmproxy...")
		wg.Add(1)
		go func() {
			defer wg.Done()
			mitmCmd := exec.Command("mitmproxy", "-w", filepath.Join(config.outputDir, "traffic.mitm"))
			if err := mitmCmd.Run(); err != nil {
				logger.Printf("mitmproxy failed: %v", err)
			}
		}()
		time.Sleep(2 * time.Second) // Give mitmproxy time to start
	}

	// Extract device data
	logger.Println("Extracting device data with ADB...")
	adbCmds := []string{
		fmt.Sprintf("su -c 'cp -r %s/databases %s/shared_prefs %s/files /sdcard/'", config.deviceDir, config.deviceDir, config.deviceDir),
		fmt.Sprintf("pull /sdcard/databases %s/databases", config.outputDir),
		fmt.Sprintf("pull /sdcard/shared_prefs %s/shared_prefs", config.outputDir),
		fmt.Sprintf("pull /sdcard/files %s/files", config.outputDir),
		"shell rm -r /sdcard/databases /sdcard/shared_prefs /sdcard/files",
	}
	for _, cmdStr := range adbCmds {
		cmd := exec.Command("adb", strings.Split(cmdStr, " ")...)
		if output, err := cmd.CombinedOutput(); err != nil {
			logger.Printf("ADB command failed (%s): %v - %s", cmdStr, err, output)
		} else {
			logger.Printf("ADB command succeeded: %s", cmdStr)
		}
	}
}

// parseData parses extracted data for secrets and endpoints
func parseData(config Config) {
	logger.Println("Parsing extracted data...")
	secrets := make(chan string, 100)
	endpoints := make(chan string, 100)
	filesChan := make(chan string, config.threads*2)

	// Worker pool for parsing
	for i := 0; i < config.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range filesChan {
				data, err := ioutil.ReadFile(file)
				if err != nil {
					logger.Printf("Failed to read %s: %v", file, err)
					continue
				}
				content := string(data)

				// Secrets regex
				secretRe := regexp.MustCompile(`(?i)(api_key|token|secret)\s*[:=]\s*["']?([^"\s]+)["']?`)
				for _, match := range secretRe.FindAllStringSubmatch(content, -1) {
					if len(match) == 3 {
						secrets <- fmt.Sprintf("%s: %s", match[1], match[2])
					}
				}

				// Endpoints regex
				endpointRe := regexp.MustCompile(`https?://[^\s"]+`)
				for _, url := range endpointRe.FindAllString(content, -1) {
					endpoints <- url
				}
			}
		}()
	}

	// Feed files to workers
	err := filepath.Walk(config.outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			filesChan <- path
		}
		return nil
	})
	if err != nil {
		logger.Printf("Failed to walk directory: %v", err)
	}
	close(filesChan)
	wg.Wait()

	// Write results
	close(secrets)
	close(endpoints)
	writeResults(filepath.Join(config.outputDir, "secrets.txt"), secrets)
	writeResults(filepath.Join(config.outputDir, "endpoints.txt"), endpoints)
}

func writeResults(filePath string, data chan string) {
	file, err := os.Create(filePath)
	if err != nil {
		logger.Printf("Failed to create %s: %v", filePath, err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	seen := make(map[string]bool)
	for item := range data {
		if !seen[item] {
			fmt.Fprintln(writer, item)
			seen[item] = true
		}
	}
	writer.Flush()
	logger.Printf("Wrote results to %s", filePath)
}