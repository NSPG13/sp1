package sp1

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestDiagnosticWitness(t *testing.T) {
	witnessPath := os.Getenv("SP1_DIAGNOSTIC_WITNESS")
	constraintsPath := os.Getenv("SP1_DIAGNOSTIC_CONSTRAINTS")
	if witnessPath == "" || constraintsPath == "" {
		t.Skip("set SP1_DIAGNOSTIC_WITNESS and SP1_DIAGNOSTIC_CONSTRAINTS")
	}
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		t.Fatal(err)
	}
	var input WitnessInput
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("CONSTRAINTS_JSON", constraintsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("SP1_DIAGNOSTIC_ASSERT_CONTEXT", "1"); err != nil {
		t.Fatal(err)
	}
	circuit := NewCircuit(input)
	witness := NewCircuit(input)
	if err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}
