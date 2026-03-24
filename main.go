package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/nickciolpan/docker-scan-lite/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	dockerfilePath string
	jsonOutput     bool
	sarifOutput    bool
	verbose        bool
	severity       string
	failOn         string
	version        = "1.0.0"
	author         = "Nick Ciolpan"
	email          = "nick@ciolpan.com"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:     "docker-scan-lite",
		Short:   "Lightweight Docker image scanner",
		Long:    `A lightweight Docker image scanner that analyzes Dockerfiles for security issues, outdated base images, exposed ports, environment variables, and secrets.`,
		Version: version,
		Run:     runScan,
	}

	rootCmd.Flags().StringVarP(&dockerfilePath, "file", "f", "Dockerfile", "Path to Dockerfile")
	rootCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output results in JSON format")
	rootCmd.Flags().BoolVar(&sarifOutput, "sarif", false, "Output results in SARIF format")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().StringVar(&severity, "severity", "", "Minimum severity to report (info, low, medium, high)")
	rootCmd.Flags().StringVar(&failOn, "exit-code", "", "Return exit code 1 if issues at or above this severity are found (info, low, medium, high)")

	rootCmd.SetVersionTemplate(fmt.Sprintf("%s version %s\nAuthor: %s (%s)\nFollow Graffino for product design and software development\n", rootCmd.Name(), version, author, email))

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) {
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		color.Red("Error: Dockerfile not found at %s", dockerfilePath)
		os.Exit(1)
	}

	s := scanner.NewScanner(dockerfilePath, verbose)
	if severity != "" {
		s.SetMinSeverity(severity)
	}

	result, err := s.Scan()
	if err != nil {
		color.Red("Error scanning Dockerfile: %v", err)
		os.Exit(1)
	}

	if sarifOutput {
		result.PrintSARIF()
	} else if jsonOutput {
		result.PrintJSON()
	} else {
		result.PrintFormatted()
	}

	if failOn != "" {
		os.Exit(result.ExitCode(failOn))
	}
}
