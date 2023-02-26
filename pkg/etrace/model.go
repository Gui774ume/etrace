/*
Copyright © 2021 GUILLAUME FOURNIER

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

package etrace

import (
	"errors"
)

const (
	// MaxDataPerArg is the maximum data length collected per argument
	MaxDataPerArg = 1024
)

// Options contains the parameters of ETrace
type Options struct {
	RawDump               bool
	JSONDump              bool
	Stdout                bool
	BytesShown            int
	Stats                 bool
	EventHandler          func(data []byte)
	hasCustomEventHandler bool
	SyscallFilters        []Syscall
	CommFilters           []string
	Follow                bool
}

func (o Options) ShouldActivateProbes() bool {
	return o.JSONDump || o.RawDump || o.Stats || o.Stdout || o.hasCustomEventHandler
}

func (o Options) SendEventsToUserSpace() bool {
	return o.JSONDump || o.RawDump || o.Stdout
}

func (o Options) IsValid() error {
	if o.JSONDump == true && o.RawDump == true {
		return errors.New("you can't activate both --json and --raw")
	}
	return nil
}

func (o Options) check() error {
	return nil
}
