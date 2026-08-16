package trusted_setup

import "testing"

func TestRequiredDomainSize(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{name: "one", in: 1, want: 1},
		{name: "exact power", in: 1 << 26, want: 1 << 26},
		{name: "next power", in: (1 << 26) + 1, want: 1 << 27},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := requiredDomainSize(test.in)
			if err != nil {
				t.Fatalf("requiredDomainSize(%d): %v", test.in, err)
			}
			if got != test.want {
				t.Fatalf("requiredDomainSize(%d) = %d, want %d", test.in, got, test.want)
			}
		})
	}
}

func TestRequiredDomainSizeRejectsNonPositiveInput(t *testing.T) {
	if _, err := requiredDomainSize(0); err == nil {
		t.Fatal("requiredDomainSize(0) succeeded")
	}
}

func TestRequireSrsCapacity(t *testing.T) {
	if err := requireSrsCapacity(100, 100); err != nil {
		t.Fatalf("exact capacity rejected: %v", err)
	}
	if err := requireSrsCapacity(99, 100); err == nil {
		t.Fatal("undersized SRS accepted")
	}
}
