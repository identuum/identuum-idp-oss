package main

import (
	"strings"
	"testing"
)

// OSS-REVIEW-FIXES-3 item 3 (licence check OSS-LICENSE-CHECK): four npm
// packages of the embedded console need more than their own licence file, and
// supplementNPM adds it to the generated notices — never a hand-kept tail.
// Each override is pinned here on synthetic components, so the tests need no
// identuum-ui checkout and no package install.

// mitFixture is an MIT licence text (React's, byte for byte) that the
// classifier reads as MIT.
const mitFixture = `MIT License

Copyright (c) Meta Platforms, Inc. and affiliates.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`

func npmFixture() []Component {
	return []Component{
		{Ecosystem: "npm", Name: "@vercel/og", Version: "0.11.1", SPDX: "MPL-2.0", Texts: []LicenseText{{File: "LICENSE", Text: "Mozilla Public License Version 2.0\n"}}},
		{Ecosystem: "npm", Name: "caniuse-lite", Version: "1.0.30001700", SPDX: "CC-BY-4.0", Texts: []LicenseText{{File: "LICENSE", Text: "Attribution 4.0 International\n"}}},
		{Ecosystem: "npm", Name: "next", Version: "16.3.8", SPDX: "MIT", Texts: []LicenseText{{File: "license.md", Text: mitFixture}}},
		{Ecosystem: "npm", Name: "react", Version: "19.2.8", SPDX: "MIT", Texts: []LicenseText{{File: "LICENSE", Text: mitFixture}}},
		{Ecosystem: "npm", Name: "@next/env", Version: "16.3.8", SPDX: "MIT"},
		{Ecosystem: "npm", Name: "client-only", Version: "0.0.1", SPDX: "MIT"},
	}
}

func fixtureComponent(t *testing.T, comps []Component, name string) Component {
	t.Helper()
	for _, c := range comps {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("%s missing from the components", name)
	return Component{}
}

// @vercel/og is MPL-2.0: the notices say where its unmodified source, at
// that version, can be obtained; its own licence text stays.
func TestSupplementNPM_VercelOGCarriesItsSourceAvailability(t *testing.T) {
	comps, err := supplementNPM(npmFixture())
	if err != nil {
		t.Fatal(err)
	}
	og := fixtureComponent(t, comps, "@vercel/og")
	for _, want := range []string{"MPL-2.0 source availability", "has not modified", "unmodified upstream source of @vercel/og 0.11.1", "https://registry.npmjs.org/@vercel/og/-/og-0.11.1.tgz"} {
		if !strings.Contains(og.Notice, want) {
			t.Errorf("@vercel/og notice %q lacks %q", og.Notice, want)
		}
	}
	if len(og.Texts) != 1 || !strings.HasPrefix(og.Texts[0].Text, "Mozilla Public License") {
		t.Errorf("@vercel/og licence texts = %+v; want its own MPL text kept", og.Texts)
	}
	if !strings.Contains(Render(sampleInputs(), []Component{og}), og.Notice) {
		t.Error("the rendered notices omit the source-availability statement")
	}
	moved := npmFixture()
	moved[0].Version = "0.12.0"
	if _, err := supplementNPM(moved); err == nil {
		t.Error("another @vercel/og version must be refused until its source pointer is reviewed")
	}
}

// caniuse-lite's data is CC-BY-4.0: the notices name the work, its authors
// and the licence.
func TestSupplementNPM_CaniuseLiteCarriesItsAttribution(t *testing.T) {
	comps, err := supplementNPM(npmFixture())
	if err != nil {
		t.Fatal(err)
	}
	c := fixtureComponent(t, comps, "caniuse-lite")
	for _, want := range []string{"Can I use", "Alexis Deveria", "Ben Briggs", "CC-BY-4.0", "https://creativecommons.org/licenses/by/4.0/"} {
		if !strings.Contains(c.Notice, want) {
			t.Errorf("caniuse-lite notice %q lacks %q", c.Notice, want)
		}
	}
	if !strings.Contains(Render(sampleInputs(), []Component{c}), c.Notice) {
		t.Error("the rendered notices omit the attribution")
	}
	relicensed := npmFixture()
	relicensed[1].SPDX = "MIT"
	if _, err := supplementNPM(relicensed); err == nil {
		t.Error("a caniuse-lite under another licence must be refused until its attribution is reviewed")
	}
}

// @next/env ships no licence file: it takes the exact MIT text of next at
// the same version, labelled with where it came from.
func TestSupplementNPM_NextEnvTakesNextsLicence(t *testing.T) {
	comps, err := supplementNPM(npmFixture())
	if err != nil {
		t.Fatal(err)
	}
	env := fixtureComponent(t, comps, "@next/env")
	if len(env.Texts) != 1 || env.Texts[0].Text != mitFixture || env.Texts[0].File != "next@16.3.8/license.md (upstream project licence)" {
		t.Errorf("@next/env texts = %+v; want next@16.3.8's licence, byte for byte, with its source label", env.Texts)
	}
	if !strings.Contains(env.Notice, "omits its licence file") {
		t.Errorf("@next/env notice = %q", env.Notice)
	}
	skewed := npmFixture()
	skewed[4].Version = "16.3.9"
	if _, err := supplementNPM(skewed); err == nil {
		t.Error("an @next/env at another version than next must be refused")
	}
	own := npmFixture()
	own[4].Texts = []LicenseText{{File: "LICENSE", Text: "its own\n"}}
	comps, err = supplementNPM(own)
	if err != nil || fixtureComponent(t, comps, "@next/env").Texts[0].Text != "its own\n" {
		t.Errorf("an @next/env shipping its own licence must keep it (err %v)", err)
	}
}

// client-only ships no licence file: it takes React's exact MIT text.
func TestSupplementNPM_ClientOnlyTakesReactsLicence(t *testing.T) {
	comps, err := supplementNPM(npmFixture())
	if err != nil {
		t.Fatal(err)
	}
	co := fixtureComponent(t, comps, "client-only")
	if len(co.Texts) != 1 || co.Texts[0].Text != mitFixture || co.Texts[0].File != "react@19.2.8/LICENSE (upstream project licence)" {
		t.Errorf("client-only texts = %+v; want react@19.2.8's licence, byte for byte, with its source label", co.Texts)
	}
	if !strings.Contains(Render(sampleInputs(), []Component{co}), mitFixture) {
		t.Error("the rendered notices omit client-only's licence text")
	}
	noReact := npmFixture()
	noReact = append(noReact[:3], noReact[4:]...)
	if _, err := supplementNPM(noReact); err == nil {
		t.Error("client-only with no React licence in the closure must be refused")
	}
}
