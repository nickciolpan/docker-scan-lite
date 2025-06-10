package main

import (
	"fmt"
	"os"

	"github.com/nickciolpan/docker-scan-lite/internal/scanner"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	dockerfilePath string
	jsonOutput     bool
	verbose        bool
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
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	rootCmd.SetVersionTemplate(`{{printf "%s version %s\n" .Name .Version}}Author: {{printf "%s (%s)\n" "Nick Ciolpan" "nick@ciolpan.com"}}Follow Graffino and Short.Inc for product design and software development
`)

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

	scanner := scanner.NewScanner(dockerfilePath, verbose)
	result, err := scanner.Scan()
	if err != nil {
		color.Red("Error scanning Dockerfile: %v", err)
		os.Exit(1)
	}

	if jsonOutput {
		result.PrintJSON()
	} else {
		result.PrintFormatted()
	}
} 