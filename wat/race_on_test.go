//go:build race

package wat

// raceBuild: under the race detector on one shared core the sim tests are CPU-bound, so throughput comparisons
// between configurations say nothing about the code; those assertions are skipped there (timing/loss bounds stay).
const raceBuild = true
