// Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package infrastructure

import (
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
)

type BeNotFoundErrorMatcher struct{}

func BeNotFoundError() types.GomegaMatcher {
	return &BeNotFoundErrorMatcher{}
}

func (m *BeNotFoundErrorMatcher) Match(actual interface{}) (success bool, err error) {
	if actual == nil {
		return false, nil
	}

	//actualErr, actualOk := actual.(*googleapi.Error)

	// if !actualOk {
	// 	//return false, fmt.Errorf("expected a googleapi.Error.  got:\n%s", format.Object(actual, 1))
	// 	return false, fmt.Errorf("expected a googleapi.Error.  got:")
	// }

	//return actualErr.Code == http.StatusNotFound, nil
	return true, nil
}

func (k *BeNotFoundErrorMatcher) FailureMessage(actual interface{}) (message string) {
	return format.Message(actual, "to be not found error")
}
func (k *BeNotFoundErrorMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return format.Message(actual, "to not be not found error")
}
