package main

import (
	"encoding/json"
	//"bytes"
	"context"
	"fmt"
	//"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	//"strings"
	//"os/exec"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type Body struct {
	Content string `json:"content"`
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	var content Body

	ctx, cancel := context.WithCancel(context.Background())

	go func(content Body, w http.ResponseWriter, r *http.Request) {
		defer cancel()
		cDir, _ := os.Getwd()

		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintf(w, "Method not allowed")
			return
		}

		// Read terraform code from request body
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Error reading request body: %v", err)
			return
		}

		err = json.Unmarshal([]byte(body), &content)
		if err != nil {
			log.Printf("Error unmarshaling data: %v\n", err)
			return
		}
		log.Println(cDir)
		err = ioutil.WriteFile(cDir+"/terraform/main.tf", []byte(content.Content), 0644)
		if err != nil {
			log.Fatal(err)
		}

		// Docker client initialization
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			log.Fatal(err)
		}

		// Define container configuration
		config := &container.Config{
			Image: "terrascan-tfsec-scanner",
			//Cmd:   []string{"/src", "--format", "csv"}, // Provide any additional arguments here
		}

		log.Println(cDir)
		hostConfig := &container.HostConfig{
			Binds: []string{
				cDir + "/terraform" + ":/src",
			},
		}

		// Create container
		resp, err := cli.ContainerCreate(context.Background(), config, hostConfig, nil, nil, "")
		if err != nil {
			log.Fatal(err)
		}

		// Start container
		if err := cli.ContainerStart(context.Background(), resp.ID, types.ContainerStartOptions{}); err != nil {
			log.Fatal(err)
		}

		// Print container ID
		fmt.Printf("Container ID: %s\n", resp.ID)

		// Wait for container to finish
		statusCh, errCh := cli.ContainerWait(context.Background(), resp.ID, container.WaitConditionNotRunning)
		select {
		case err := <-errCh:
			if err != nil {
				log.Fatal(err)
			}
		case <-statusCh:
		}

		// Retrieve container logs
		/*
			logs, err := cli.ContainerLogs(context.Background(), resp.ID, types.ContainerLogsOptions{ShowStdout: true})
			if err != nil {
				log.Fatal(err)
			}

			// Read and print logs
			logBytes, err := ioutil.ReadAll(logs)
			cleanedLine := strings.ReplaceAll(string(logBytes), "^A^@^@^@^@^@^@B", "")

			if err != nil {
				log.Fatal(err)
			}
			err = ioutil.WriteFile(cDir+"/output.json", []byte(cleanedLine), 0644)
			if err != nil {
				log.Fatal(err)
			}
		*/

		// read results
		data, err := ioutil.ReadFile(cDir + "/terraform/results.json")
		if err != nil {
			log.Fatalf("Error reading JSON file: %v", err)
		}

		// generate return data
		responseJSON, err := json.Marshal(data)
		if err != nil {
			http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
			return
		}

		//fmt.Printf("Container Logs:\n%s\n", cleanedLine)
		// write response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(responseJSON)
	}(content, w, r)

	select {
	case <-ctx.Done():
		return
	}
}

func main() {
	http.HandleFunc("/scan", handleScan)
	fmt.Println("Server listening on port 8081")
	http.ListenAndServe(":8081", nil)
}
