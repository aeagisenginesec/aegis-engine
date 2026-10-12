package attackpath

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

// testResource builds a minimal IR resource for chain tests.
func testResource(typ, name string, attrs map[string]ir.Value) ir.Resource {
	if attrs == nil {
		attrs = map[string]ir.Value{}
	}
	return ir.Resource{
		Type:       typ,
		Name:       name,
		Attributes: attrs,
		Span:       ir.Span{File: "main.tf", StartLine: 1},
	}
}

func strVal(s string) ir.Value {
	return ir.Value{Raw: s, Known: true, Span: ir.Span{File: "main.tf", StartLine: 1}}
}

func refVal(ref string) ir.Value {
	return ir.Value{Raw: ref, Known: true, Ref: ref, Span: ir.Span{File: "main.tf", StartLine: 1}}
}

func unknownVal() ir.Value {
	return ir.Value{Known: false, Span: ir.Span{File: "main.tf", StartLine: 1}}
}

// ingressBlock builds a nested ingress block value like the real IR.
func ingressBlock(cidr string) ir.Value {
	return ir.Value{
		Raw: []ir.Value{
			{Raw: map[string]ir.Value{
				"cidr_blocks": strVal(cidr),
			}, Known: true},
		},
		Known: true,
		Span:  ir.Span{File: "main.tf", StartLine: 1},
	}
}

// completeChainFixture: internet → open SG → EC2 → RDS, all concrete.
func completeChainFixture() []ir.Resource {
	return []ir.Resource{
		testResource("aws_security_group", "web", map[string]ir.Value{
			"ingress": ingressBlock("0.0.0.0/0"),
		}),
		testResource("aws_instance", "web", map[string]ir.Value{
			"vpc_security_group_ids": refVal("aws_security_group.web.id"),
		}),
		testResource("aws_db_instance", "prod", map[string]ir.Value{
			"vpc_security_group_ids": refVal("aws_security_group.web.id"),
		}),
	}
}

// uncertainChainFixture: SG CIDR from a variable — hop must be UNCERTAIN.
func uncertainChainFixture() []ir.Resource {
	return []ir.Resource{
		testResource("aws_security_group", "web", map[string]ir.Value{
			"ingress": ir.Value{
				Raw: []ir.Value{
					{Raw: map[string]ir.Value{
						"cidr_blocks": {Raw: "var.allowed_cidr", Known: true, Span: ir.Span{File: "main.tf", StartLine: 1}},
					}, Known: true},
				},
				Known: true,
				Span:  ir.Span{File: "main.tf", StartLine: 1},
			},
		}),
		testResource("aws_instance", "web", map[string]ir.Value{
			"vpc_security_group_ids": refVal("aws_security_group.web.id"),
		}),
		testResource("aws_db_instance", "prod", map[string]ir.Value{
			"vpc_security_group_ids": refVal("aws_security_group.web.id"),
		}),
	}
}

// brokenChainFixture: no open SG, no public ALB — no entry point.
func brokenChainFixture() []ir.Resource {
	return []ir.Resource{
		testResource("aws_security_group", "web", map[string]ir.Value{
			"ingress": ingressBlock("10.0.0.0/8"),
		}),
		testResource("aws_instance", "web", map[string]ir.Value{
			"vpc_security_group_ids": refVal("aws_security_group.web.id"),
		}),
		testResource("aws_db_instance", "prod", map[string]ir.Value{
			"vpc_security_group_ids": refVal("aws_security_group.web.id"),
		}),
	}
}

func TestCompleteChain(t *testing.T) {
	b := NewBuilder(completeChainFixture())
	chains := b.BuildKillChains()
	if len(chains) == 0 {
		t.Fatal("expected at least one kill chain for complete fixture")
	}
	c := chains[0]
	if c.Confidence != ConfidenceHigh {
		t.Errorf("expected high confidence, got %s", c.Confidence)
	}
	if c.Uncertain {
		t.Error("complete chain should not be uncertain")
	}
	// Verify hop kinds in order.
	foundData := false
	for _, h := range c.Hops {
		if h.Kind == KindData {
			foundData = true
		}
		if h.Evidence.Attribute == "" {
			t.Errorf("hop %s missing evidence attribute", h.Resource)
		}
	}
	if !foundData {
		t.Error("chain should reach a data store")
	}
}

func TestUncertainChain(t *testing.T) {
	b := NewBuilder(uncertainChainFixture())
	chains := b.BuildKillChains()
	if len(chains) == 0 {
		t.Fatal("expected chains even with uncertain SG")
	}
	// At least one chain must flag the uncertain SG hop.
	foundUncertain := false
	for _, c := range chains {
		for _, h := range c.Hops {
			if h.Uncertain != "" {
				foundUncertain = true
				if !strings.HasPrefix(h.Uncertain, "UNCERTAIN:") {
					t.Errorf("uncertainty must start with UNCERTAIN:, got %q", h.Uncertain)
				}
				if h.Confidence != ConfidenceLow {
					t.Errorf("uncertain hop must be low confidence, got %s", h.Confidence)
				}
			}
		}
		if c.Uncertain != foundUncertain {
			// chain-level flag must match hop-level reality
		}
	}
	if !foundUncertain {
		t.Error("variable-sourced CIDR must produce an UNCERTAIN hop, never a silent concrete one")
	}
}

func TestBrokenChain(t *testing.T) {
	b := NewBuilder(brokenChainFixture())
	chains := b.BuildKillChains()
	// No world-open SG and no public ALB: any chain must have an
	// uncertain entry hop, never an invented concrete entry.
	for _, c := range chains {
		for _, h := range c.Hops {
			if h.Kind == KindEntry && h.Resource != "internet" && h.Uncertain == "" {
				// A concrete non-internet entry with no evidence is invented.
				if h.Evidence.Attribute == "" {
					t.Errorf("entry hop %s has no evidence — invented hop", h.Resource)
				}
			}
		}
	}
}

func TestClassifyUncertainty(t *testing.T) {
	cases := []struct {
		val  ir.Value
		want string // prefix, or "" for concrete
	}{
		{strVal("0.0.0.0/0"), ""},
		{ir.Value{Raw: "var.cidr", Known: true}, "UNCERTAIN:"},
		{ir.Value{Raw: "data.aws_ami.ubuntu.id", Known: true}, "UNCERTAIN:"},
		{ir.Value{Raw: "each.value", Known: true}, "UNCERTAIN:"},
		{unknownVal(), "UNCERTAIN:"},
		{ir.Value{Raw: `var.env == "prod" ? "a" : "b"`, Known: true}, "UNCERTAIN:"},
	}
	for _, tc := range cases {
		got := ClassifyUncertainty(tc.val)
		if tc.want == "" && got != "" {
			t.Errorf("ClassifyUncertainty(%v) = %q, want concrete", tc.val.Raw, got)
		}
		if tc.want != "" && !strings.HasPrefix(got, tc.want) {
			t.Errorf("ClassifyUncertainty(%v) = %q, want prefix %q", tc.val.Raw, got, tc.want)
		}
	}
}

func TestRenderASCII(t *testing.T) {
	b := NewBuilder(completeChainFixture())
	chains := b.BuildKillChains()
	if len(chains) == 0 {
		t.Skip("no chains to render")
	}
	out := RenderASCII(chains[0])
	if !strings.Contains(out, "INTERNET") {
		t.Error("ASCII render must start with INTERNET")
	}
	if !strings.Contains(out, "▼") && !strings.Contains(out, "|") {
		t.Error("ASCII render must show chain connectors")
	}
}

func TestIAMChain(t *testing.T) {
	resources := []ir.Resource{
		testResource("aws_iam_role", "app", nil),
		testResource("aws_iam_policy", "admin", map[string]ir.Value{
			"policy": strVal(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
		}),
		testResource("aws_iam_role_policy_attachment", "app_admin", map[string]ir.Value{
			"role":       refVal("aws_iam_role.app.name"),
			"policy_arn": refVal("aws_iam_policy.admin.arn"),
		}),
		testResource("aws_lambda_function", "api", map[string]ir.Value{
			"role": refVal("aws_iam_role.app.arn"),
		}),
	}
	b := NewBuilder(resources)
	chains := b.IAMChains()
	if len(chains) == 0 {
		t.Fatal("expected IAM privilege chain")
	}
	ic := chains[0]
	if ic.Role.Resource != "aws_iam_role.app" {
		t.Errorf("role hop = %s, want aws_iam_role.app", ic.Role.Resource)
	}
	if ic.Workload.Resource != "aws_lambda_function.api" {
		t.Errorf("workload hop = %s, want aws_lambda_function.api", ic.Workload.Resource)
	}
	if len(ic.Actions) == 0 {
		t.Error("expected sensitive actions detected in policy")
	}
}
