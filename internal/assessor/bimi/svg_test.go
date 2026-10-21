package bimi

import (
	"os"
	"testing"
)

func TestInspectLogoSkipsIllustratorComment(t *testing.T) {
	t.Parallel()
	body := []byte("<?xml version=\"1.0\"?>\n<!-- Generator: Adobe Illustrator -->\n<svg version=\"1.2\" baseProfile=\"tiny-ps\"><title>CNN</title></svg>")
	got := InspectLogo(body, "image/svg+xml")
	if !got.StartsWithSVG || !got.BaseProfileTinyPS || !got.Version12 || !got.HasTitle || got.HasScript {
		t.Fatalf("%+v", got)
	}
	if findings := logoFindings(got); len(findings) != 0 {
		t.Fatalf("findings %q", findings)
	}
}

func TestInspectLogoFixtures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		file                 string
		ct                   string
		starts, profile, ver bool
		title, script        bool
		findings             []string
	}{
		{
			file: "testdata/logo-tiny-ps.svg", ct: "image/svg+xml",
			starts: true, profile: true, ver: true, title: true,
		},
		{
			file: "testdata/logo-script.svg", ct: "image/svg+xml",
			starts: true, profile: true, ver: true, title: true, script: true,
			findings: []string{"logo contains <script"},
		},
		{
			file: "testdata/logo-plain.svg", ct: "image/svg+xml",
			starts: true,
			findings: []string{
				`logo missing baseProfile="tiny-ps"`,
				"logo version is not 1.2",
				"logo missing <title>",
			},
		},
		{
			file: "testdata/not-svg.txt", ct: "text/plain",
			findings: []string{"logo does not start with <svg"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			body, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatal(err)
			}
			got := InspectLogo(body, tc.ct)
			if got.ContentType != tc.ct || got.Bytes != len(body) || got.StartsWithSVG != tc.starts || got.BaseProfileTinyPS != tc.profile || got.Version12 != tc.ver || got.HasTitle != tc.title || got.HasScript != tc.script {
				t.Fatalf("%+v", got)
			}
			findings := logoFindings(got)
			if len(findings) != len(tc.findings) {
				t.Fatalf("findings %q want %q", findings, tc.findings)
			}
			for i := range tc.findings {
				if findings[i] != tc.findings[i] {
					t.Fatalf("findings %q want %q", findings, tc.findings)
				}
			}
		})
	}
}
