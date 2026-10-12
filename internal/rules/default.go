// Package rules wires the rule packs into registries.
package rules

// DefaultRegistry returns a registry with every known rule pack registered.
// Prefer RegistryFor for pack selection.
func DefaultRegistry() *Registry {
	return RegistryFor("all")
}
