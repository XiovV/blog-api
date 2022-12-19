package validator

import "fmt"

type Validator struct {
	errors []string
}

func New() *Validator {
	return &Validator{errors: []string{}}
}

func (v *Validator) RequiredMax(key, value string, max int) {
	if len(value) > max {
		v.addError(fmt.Sprintf("%s cannot be longer than %d characters", key, max))
	}
}

func (v *Validator) RequiredRange(key, value string, min, max int) {
	v.RequiredMax(key, value, max)
	v.RequiredMin(key, value, min)
}

func (v *Validator) RequiredExact(key, value string, n int) {
	if len(value) != n {
		v.addError(fmt.Sprintf("%s must be exactly %d characters long", key, n))
	}
}

func (v *Validator) RequiredMin(key, value string, min int) {
	if len(value) < min {
		v.addError(fmt.Sprintf("%s must be at least %d characters long", key, min))
	}
}

func (v *Validator) IsValid() (bool, []string) {
	if len(v.errors) > 0 {
		return false, v.errors
	}

	return true, nil
}

func (v *Validator) addError(err string) {
	v.errors = append(v.errors, err)
}
