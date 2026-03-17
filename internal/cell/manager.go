package cell

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/alandtse/poc-cell-oauth/pkg/models"
)

// Manager tracks all cells, their health, and handles failover redistribution.
type Manager struct {
	mu              sync.RWMutex
	cells           map[string]*models.CellInfo
	healthInterval  time.Duration
	healthThreshold int // consecutive failures before marking unhealthy
	failureCounts   map[string]int
	onCellDown      func(cellID string) // callback when a cell goes down
	stopCh          chan struct{}
}

func NewManager(healthInterval time.Duration, onCellDown func(string)) *Manager {
	return &Manager{
		cells:           make(map[string]*models.CellInfo),
		healthInterval:  healthInterval,
		healthThreshold: 3,
		failureCounts:   make(map[string]int),
		onCellDown:      onCellDown,
		stopCh:          make(chan struct{}),
	}
}

func (m *Manager) Register(cell *models.CellInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cell.Healthy = true
	cell.LastCheck = time.Now()
	m.cells[cell.ID] = cell
	m.failureCounts[cell.ID] = 0
	log.Printf("[cell-manager] registered cell %s at %s", cell.ID, cell.Address)
}

func (m *Manager) Unregister(cellID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cells, cellID)
	delete(m.failureCounts, cellID)
	log.Printf("[cell-manager] unregistered cell %s", cellID)
}

func (m *Manager) GetCell(cellID string) (*models.CellInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.cells[cellID]
	return c, ok
}

func (m *Manager) GetHealthyCells() []*models.CellInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var healthy []*models.CellInfo
	for _, c := range m.cells {
		if c.Healthy {
			healthy = append(healthy, c)
		}
	}
	return healthy
}

func (m *Manager) GetAllCells() []*models.CellInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var all []*models.CellInfo
	for _, c := range m.cells {
		all = append(all, c)
	}
	return all
}

// GetLeastLoadedCell returns the healthy cell with the lowest current load.
func (m *Manager) GetLeastLoadedCell() (*models.CellInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var best *models.CellInfo
	for _, c := range m.cells {
		if !c.Healthy {
			continue
		}
		if best == nil || c.CurrentLoad < best.CurrentLoad {
			best = c
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no healthy cells available")
	}
	return best, nil
}

// StartHealthChecks begins periodic health checking of all cells.
func (m *Manager) StartHealthChecks() {
	go func() {
		ticker := time.NewTicker(m.healthInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.checkAllCells()
			case <-m.stopCh:
				return
			}
		}
	}()
	log.Printf("[cell-manager] health checks started (interval=%s)", m.healthInterval)
}

func (m *Manager) Stop() {
	close(m.stopCh)
}

func (m *Manager) checkAllCells() {
	m.mu.RLock()
	cellsCopy := make(map[string]*models.CellInfo)
	for k, v := range m.cells {
		cellsCopy[k] = v
	}
	m.mu.RUnlock()

	client := &http.Client{Timeout: 5 * time.Second}

	for _, cell := range cellsCopy {
		go func(c *models.CellInfo) {
			healthy := m.checkCell(client, c)
			m.mu.Lock()
			defer m.mu.Unlock()

			if healthy {
				m.failureCounts[c.ID] = 0
				c.Healthy = true
				c.LastCheck = time.Now()
			} else {
				m.failureCounts[c.ID]++
				if m.failureCounts[c.ID] >= m.healthThreshold && c.Healthy {
					c.Healthy = false
					c.LastCheck = time.Now()
					log.Printf("[cell-manager] cell %s marked UNHEALTHY after %d failures",
						c.ID, m.failureCounts[c.ID])
					if m.onCellDown != nil {
						go m.onCellDown(c.ID)
					}
				}
			}
		}(cell)
	}
}

func (m *Manager) checkCell(client *http.Client, cell *models.CellInfo) bool {
	resp, err := client.Get(fmt.Sprintf("http://%s/health", cell.Address))
	if err != nil {
		log.Printf("[cell-manager] health check failed for %s: %v", cell.ID, err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var health models.CellHealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return false
	}

	cell.CurrentLoad = health.CurrentLoad
	return health.Status == "healthy" || health.Status == "degraded"
}

// CalculateCapacityPerCell returns the target load each cell should handle
// following the N-1 rule: with N cells, each must be able to handle 1/(N-1) of total.
func (m *Manager) CalculateCapacityPerCell() float64 {
	healthy := m.GetHealthyCells()
	n := len(healthy)
	if n <= 1 {
		return 1.0
	}
	// Each cell should operate at (N-1)/N capacity normally
	// so it can absorb 1/(N-1) additional load if one cell fails
	return float64(n-1) / float64(n)
}
