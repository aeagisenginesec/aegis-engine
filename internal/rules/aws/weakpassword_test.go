package aws

import (
	"strings"
	"testing"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
)

func Test850_WeakFires(t *testing.T) {
	for _, pw := range []string{"password123", "Password123!", "Admin2024", "changeme", "short1!", ""} {
		r := res("aws_db_instance", "dev", map[string]ir.Value{
			"password": ks(pw, 3),
		})
		f := runRule(dbWeakPassword{}, r)
		if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-850" {
			t.Errorf("password %q: expected 850 to fire, got %+v", pw, f)
			continue
		}
		if pw != "" && (strings.Contains(f[0].Evidence.Actual, pw) || strings.Contains(f[0].Description, pw)) {
			t.Errorf("password %q: finding must never carry the password value", pw)
		}
	}
}

func Test850_StrongQuiet(t *testing.T) {
	for _, pw := range []string{"Str0ng-4c2865-Db!", "x9#Qw2!zL8$vN4&pR7", "correct-horse-battery-staple-99"} {
		r := res("aws_db_instance", "dev", map[string]ir.Value{
			"password": ks(pw, 3),
		})
		if f := runRule(dbWeakPassword{}, r); len(f) != 0 {
			t.Errorf("password %q: expected quiet, got %+v", pw, f)
		}
	}
}

func Test850_UnknownAndVarQuiet(t *testing.T) {
	r := res("aws_db_instance", "dev", map[string]ir.Value{"password": ku(3)})
	if f := runRule(dbWeakPassword{}, r); len(f) != 0 {
		t.Fatalf("unknown password must stay quiet, got %+v", f)
	}
	r2 := res("aws_db_instance", "dev", map[string]ir.Value{})
	if f := runRule(dbWeakPassword{}, r2); len(f) != 0 {
		t.Fatalf("absent password must stay quiet, got %+v", f)
	}
}

func Test850_ClusterAndRedshiftAttrs(t *testing.T) {
	cases := []struct {
		typ  string
		attr string
	}{
		{"aws_rds_cluster", "master_password"},
		{"aws_redshift_cluster", "master_password"},
		{"aws_redshift_cluster", "master_user_password"},
		{"aws_docdb_cluster", "master_password"},
		{"aws_neptune_cluster", "master_password"},
	}
	for _, tc := range cases {
		r := res(tc.typ, "c", map[string]ir.Value{tc.attr: ks("password123", 3)})
		if f := runRule(dbWeakPassword{}, r); len(f) != 1 {
			t.Errorf("%s.%s: expected 850 to fire, got %+v", tc.typ, tc.attr, f)
		}
	}
}

// Test850_EndToEndR3009: the round-3 gap shape — an RDS instance with
// the weak default password — fires, while the sibling instance with a
// strong password stays quiet.
func Test850_EndToEndR3009(t *testing.T) {
	src := `resource "aws_db_instance" "dev" {
  engine = "postgres"
  instance_class = "db.t3.micro"
  username = "postgres"
  password = "password123"
}
resource "aws_db_instance" "ephemeral" {
  engine = "postgres"
  instance_class = "db.t3.micro"
  username = "appadmin"
  password = "Str0ng-4c2865-Db!"
}
`
	mod, _, err := (terraform.Adapter{}).ParseModule("t.tf", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, r := range mod.Resources {
		f := runRule(dbWeakPassword{}, r)
		if r.Name == "dev" && len(f) != 1 {
			t.Fatalf("dev (password123) must fire 850, got %+v", f)
		}
		if r.Name == "ephemeral" && len(f) != 0 {
			t.Fatalf("ephemeral (strong) must stay quiet, got %+v", f)
		}
	}
}
