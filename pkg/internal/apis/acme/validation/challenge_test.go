/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package validation

import (
	"fmt"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmacmev1 "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	cmacmev1alpha2 "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"
	cmacmev1alpha3 "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha3"
	cmacmev1beta1 "github.com/jetstack/cert-manager/pkg/apis/acme/v1beta1"
	"github.com/jetstack/cert-manager/pkg/internal/api/validation"
	cmacme "github.com/jetstack/cert-manager/pkg/internal/apis/acme"
)

func TestValidateChallengeUpdate(t *testing.T) {
	baseChal := &cmacme.Challenge{
		Spec: cmacme.ChallengeSpec{
			URL: "testurl",
		},
	}

	scenarios := map[string]struct {
		old, new *cmacme.Challenge
		errs     []*field.Error
		warnings validation.WarningList
	}{
		"allows setting challenge spec for the first time": {
			new: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
		},
		"disallow updating challenge spec": {
			old: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			new: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "newtesturl",
				},
			},
			errs: []*field.Error{
				field.Forbidden(field.NewPath("spec"), "challenge spec is immutable after creation"),
			},
		},
		"allow updating challenge spec if no changes are made": {
			old: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			new: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
		},
		"challenge updated to v1alpha2 version": {
			old: baseChal,
			new: &cmacme.Challenge{
				TypeMeta: metav1.TypeMeta{
					APIVersion: cmacmev1alpha2.SchemeGroupVersion.String(),
					Kind:       "Challenge",
				},
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			warnings: validation.WarningList{
				fmt.Sprintf(deprecationMessageTemplate,
					cmacmev1alpha2.SchemeGroupVersion.String(),
					"Challenge",
					cmacmev1.SchemeGroupVersion.String(),
					"Challenge"),
			},
		},
		"challenge updated to v1alpha3 version": {
			old: baseChal,
			new: &cmacme.Challenge{
				TypeMeta: metav1.TypeMeta{
					APIVersion: cmacmev1alpha3.SchemeGroupVersion.String(),
					Kind:       "Challenge",
				},
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			warnings: validation.WarningList{
				fmt.Sprintf(deprecationMessageTemplate,
					cmacmev1alpha3.SchemeGroupVersion.String(),
					"Challenge",
					cmacmev1.SchemeGroupVersion.String(),
					"Challenge"),
			},
		},
		"challenge updated to v1beta1 version": {
			old: baseChal,
			new: &cmacme.Challenge{
				TypeMeta: metav1.TypeMeta{
					APIVersion: cmacmev1beta1.SchemeGroupVersion.String(),
					Kind:       "Challenge",
				},
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			warnings: validation.WarningList{
				fmt.Sprintf(deprecationMessageTemplate,
					cmacmev1beta1.SchemeGroupVersion.String(),
					"Challenge",
					cmacmev1.SchemeGroupVersion.String(),
					"Challenge"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs, warnings := ValidateChallengeUpdate(nil, s.old, s.new)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected errors %v but got %v", expectedErr, e)
				}
			}
			if !reflect.DeepEqual(warnings, s.warnings) {
				t.Errorf("Expected warnings %+#v but got %+#v", s.warnings, warnings)
			}
		})
	}
}

func TestValidateChallenge(t *testing.T) {
	scenarios := map[string]struct {
		chal     *cmacme.Challenge
		errs     []*field.Error
		warnings validation.WarningList
	}{
		"challenge updated to v1alpha2 version": {
			chal: &cmacme.Challenge{
				TypeMeta: metav1.TypeMeta{
					APIVersion: cmacmev1alpha2.SchemeGroupVersion.String(),
					Kind:       "Challenge",
				},
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			warnings: validation.WarningList{
				fmt.Sprintf(deprecationMessageTemplate,
					cmacmev1alpha2.SchemeGroupVersion.String(),
					"Challenge",
					cmacmev1.SchemeGroupVersion.String(),
					"Challenge"),
			},
		},
		"challenge updated to v1alpha3 version": {
			chal: &cmacme.Challenge{
				TypeMeta: metav1.TypeMeta{
					APIVersion: cmacmev1alpha3.SchemeGroupVersion.String(),
					Kind:       "Challenge",
				},
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			warnings: validation.WarningList{
				fmt.Sprintf(deprecationMessageTemplate,
					cmacmev1alpha3.SchemeGroupVersion.String(),
					"Challenge",
					cmacmev1.SchemeGroupVersion.String(),
					"Challenge"),
			},
		},
		"challenge updated to v1beta1 version": {
			chal: &cmacme.Challenge{
				TypeMeta: metav1.TypeMeta{
					APIVersion: cmacmev1beta1.SchemeGroupVersion.String(),
					Kind:       "Challenge",
				},
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			warnings: validation.WarningList{
				fmt.Sprintf(deprecationMessageTemplate,
					cmacmev1beta1.SchemeGroupVersion.String(),
					"Challenge",
					cmacmev1.SchemeGroupVersion.String(),
					"Challenge"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs, warnings := ValidateChallenge(nil, s.chal)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected errors %v but got %v", expectedErr, e)
				}
			}
			if !reflect.DeepEqual(warnings, s.warnings) {
				t.Errorf("Expected warnings %+#v but got %+#v", s.warnings, warnings)
			}
		})
	}
}
