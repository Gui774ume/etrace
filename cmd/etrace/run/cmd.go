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

package run

import (
	"github.com/spf13/cobra"
)

// Etrace represents the base command of etrace
var Etrace = &cobra.Command{
	Use:  "etrace",
	RunE: etraceCmd,
}

var options CLIOptions

func init() {
	Etrace.Flags().VarP(
		NewLogLevelSanitizer(&options.LogLevel),
		"log-level",
		"l",
		"log level, options: panic, fatal, error, warn, info, debug or trace")
	Etrace.Flags().BoolVar(
		&options.ETraceOptions.RawDump,
		"raw",
		false,
		"dump the data retrieved from kernel space without parsing it, use this option instead of the --json option to reduce the amount of lost events. You can ask ETrace to parse a raw dump using the --input option")
	Etrace.Flags().BoolVar(
		&options.ETraceOptions.JSONDump,
		"json",
		false,
		"parse and dump the data retrieved from kernel space in the JSON format. This option might lead to more lost events than the --raw option and more CPU usage")
	Etrace.Flags().BoolVar(
		&options.ETraceOptions.Stdout,
		"stdout",
		false,
		"parse and dump the data retrieved from kernel space to the console. This option might lead to more lost events than the --raw option and more CPU usage.")
	Etrace.Flags().IntVar(
		&options.ETraceOptions.BytesShown,
		"bytes",
		8,
		"amount of bytes shown to the screen when --stdout is provided")
	Etrace.Flags().BoolVar(
		&options.ETraceOptions.Stats,
		"stats",
		true,
		"show syscall statistics")
	Etrace.Flags().BoolVar(
		&options.ETraceOptions.Follow,
		"follow",
		true,
		"defines if etrace should trace the children of the processes that match the provided comm (works only for newly created children)")
	Etrace.Flags().StringArrayVarP(
		&options.ETraceOptions.CommFilters,
		"comm",
		"c",
		[]string{},
		"list of process comms to filter, leave empty to capture everything")
	Etrace.Flags().StringArrayVarP(
		&options.SyscallFilters,
		"syscall",
		"s",
		[]string{},
		"list of syscalls to filter, leave empty to capture everything")
	Etrace.Flags().StringVar(
		&options.InputFile,
		"input",
		"",
		"input file to parse data from")
}
