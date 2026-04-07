package commands

import "errors"

// ErrSimulationNotAvailable is returned by all simulation commands.
// These commands require Phase 100-M (simulation API endpoints) which is not
// yet available.
var ErrSimulationNotAvailable = errors.New("simulation commands require Phase 100-M (simulation API not yet available)")

// RunSimulationRun is a stub for the simulation run command.
// It returns ErrSimulationNotAvailable until the simulation API is implemented.
func RunSimulationRun() error {
	return ErrSimulationNotAvailable
}

// RunSimulationStatus is a stub for the simulation status command.
// It returns ErrSimulationNotAvailable until the simulation API is implemented.
func RunSimulationStatus() error {
	return ErrSimulationNotAvailable
}

// RunSimulationReport is a stub for the simulation report command.
// It returns ErrSimulationNotAvailable until the simulation API is implemented.
func RunSimulationReport() error {
	return ErrSimulationNotAvailable
}
