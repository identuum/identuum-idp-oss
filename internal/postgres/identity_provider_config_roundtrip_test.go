package postgres

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-V0.9.6 Part B: an identity provider's config is stored as JSON through
// providerConfigDTO, and email_domains was not in it — every provider created
// through the API lost its domain allow-list on save, so the upstream sign-in's
// email_domains gate refused every user (FUNC-H4's success path could never
// pass on a real database; the service tests used an in-memory repository).
// Every field of domain.ProviderConfig, set by reflection, must survive the
// round trip, so a field added later cannot be dropped the same way.
func TestProviderConfig_EveryFieldSurvivesTheStoredJSON(t *testing.T) {
	var in domain.ProviderConfig
	v := reflect.ValueOf(&in).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.String:
			f.SetString("value-" + v.Type().Field(i).Name)
		case reflect.Int:
			f.SetInt(int64(i + 1))
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Slice:
			f.Set(reflect.ValueOf([]string{"a-" + v.Type().Field(i).Name, "b"}))
		case reflect.Map:
			f.Set(reflect.ValueOf(map[string]string{"k": v.Type().Field(i).Name}))
		case reflect.Pointer:
			f.Set(reflect.ValueOf(&domain.TLSOptions{InsecureSkipVerify: true, DisableTLS: true}))
		default:
			t.Fatalf("field %s has kind %s, which this test does not set — extend it", v.Type().Field(i).Name, f.Kind())
		}
	}
	raw, err := json.Marshal(toProviderConfigDTO(in))
	if err != nil {
		t.Fatal(err)
	}
	var dto providerConfigDTO
	if err := json.Unmarshal(raw, &dto); err != nil {
		t.Fatal(err)
	}
	out := dto.toDomain()
	ov := reflect.ValueOf(out)
	for i := 0; i < v.NumField(); i++ {
		if !reflect.DeepEqual(v.Field(i).Interface(), ov.Field(i).Interface()) {
			t.Errorf("ProviderConfig.%s is lost when the config is stored", v.Type().Field(i).Name)
		}
	}
}
