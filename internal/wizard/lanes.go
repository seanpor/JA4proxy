package wizard

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type ShellLaneManager struct {
	LaneEnvScript string // path to scripts/lane-env.sh
	WorkDir       string // project root directory
}

func NewShellLaneManager(laneEnvScript, workDir string) *ShellLaneManager {
	return &ShellLaneManager{LaneEnvScript: laneEnvScript, WorkDir: workDir}
}

type laneEnvJSON struct {
	Lanes []LaneInfo `json:"lanes"`
}

func (m *ShellLaneManager) ListLanes(ctx context.Context) ([]LaneInfo, error) {
	if m.LaneEnvScript == "" {
		return nil, nil
	}
	cmd := exec.CommandContext(ctx, m.LaneEnvScript, "--list")
	cmd.Dir = m.WorkDir
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("lane-env.sh --list: %w", err)
	}
	var result laneEnvJSON
	if err := json.Unmarshal(output, &result); err != nil {
		return detectLanesFromFS(m.WorkDir)
	}
	return result.Lanes, nil
}

func (m *ShellLaneManager) AssignLane(ctx context.Context, preferred int) (LaneInfo, error) {
	if preferred >= 0 {
		ports, err := m.PreviewPorts(preferred)
		if err != nil {
			return LaneInfo{}, err
		}
		return LaneInfo{
			Number:  preferred,
			Name:    fmt.Sprintf("lane-%d", preferred),
			Path:    m.WorkDir,
			Ports:   ports,
			Project: fmt.Sprintf("ja4proxy-lane%d", preferred),
		}, nil
	}
	lanes, err := m.ListLanes(ctx)
	if err != nil {
		lanes = nil
	}
	used := make(map[int]bool)
	for _, l := range lanes {
		used[l.Number] = true
	}
	for i := 0; i < 40; i++ {
		if !used[i] {
			ports, err := m.PreviewPorts(i)
			if err != nil {
				return LaneInfo{}, err
			}
			return LaneInfo{
				Number:  i,
				Name:    fmt.Sprintf("lane-%d", i),
				Path:    m.WorkDir,
				Ports:   ports,
				Project: fmt.Sprintf("ja4proxy-lane%d", i),
			}, nil
		}
	}
	return LaneInfo{}, fmt.Errorf("all 40 lanes are in use")
}

func (m *ShellLaneManager) PreviewPorts(lane int) (map[string]int, error) {
	return computeLanePorts(lane), nil
}

func computeLanePorts(lane int) map[string]int {
	return map[string]int{
		"INGRESS":    443 + lane*100,
		"DIRECT":     8081 + lane*100,
		"MANAGEMENT": 8090 + lane*100,
		"METRICS":    9090 + lane*100,
		"PROMETHEUS": 9091 + lane*100,
		"GRAFANA":    3000 + lane*100,
	}
}

func detectLanesFromFS(workDir string) ([]LaneInfo, error) {
	entries, err := os.ReadDir(workDir)
	if err != nil {
		return nil, err
	}
	var lanes []LaneInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), ".env") {
			continue
		}
		info, err := parseEnvFile(filepath.Join(workDir, e.Name()))
		if err != nil {
			continue
		}
		if laneStr, ok := info["JA4_LANE"]; ok {
			laneNum, err := strconv.Atoi(laneStr)
			if err != nil {
				continue
			}
			lanes = append(lanes, LaneInfo{
				Number:  laneNum,
				Name:    info["JA4_LANE_NAME"],
				Path:    filepath.Join(workDir, e.Name()),
				Ports:   computeLanePorts(laneNum),
				Project: info["COMPOSE_PROJECT_NAME"],
			})
		}
	}
	return lanes, nil
}

func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	env := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			env[parts[0]] = parts[1]
		}
	}
	return env, scanner.Err()
}

func mergeEnvPreserveSecrets(existingPath string, newEnv map[string]string) (map[string]string, error) {
	existing, err := parseEnvFile(existingPath)
	if err != nil {
		if os.IsNotExist(err) {
			return newEnv, nil
		}
		return nil, err
	}

	for k, v := range existing {
		if isSecretEnvKey(k) && v != "" {
			newEnv[k] = v
		}
	}
	return newEnv, nil
}
