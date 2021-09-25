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
	"fmt"
	"os"
	"os/signal"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/Gui774ume/etrace/pkg/etrace"
)

func etraceCmd(cmd *cobra.Command, args []string) error {
	// Set log level
	logrus.SetLevel(options.LogLevel)

	if len(options.SyscallFilters) > 0 {
		for _, s := range options.SyscallFilters {
			newSyscall := etrace.ParseSyscallName(s)
			if newSyscall == -1 {
				return errors.Errorf("unknown syscall: %s", s)
			}
			options.ETraceOptions.SyscallFilters = append(options.ETraceOptions.SyscallFilters, newSyscall)
		}
	}

	if len(options.InputFile) > 0 {
		options.ETraceOptions.RawDump = false
		options.ETraceOptions.JSONDump = false
		options.ETraceOptions.Stdout = false
		options.ETraceOptions.Stats = false
	}

	// create a new ETrace instance
	trace, err := etrace.NewETrace(options.ETraceOptions)
	if err != nil {
		return errors.Wrap(err, "couldn't create a new ETracer")
	}

	// start ETrace
	if options.ETraceOptions.ShouldActivateProbe() {
		if err := trace.Start(); err != nil {
			return errors.Wrap(err, "couldn't start")
		}
		logrus.Infoln("Tracing started ... (Ctrl + C to stop)\n")
		if len(trace.DumpFile) > 0 {
			logrus.Infof("output file: %s", trace.DumpFile)
		}

		wait()

	} else if len(options.InputFile) > 0 {
		logrus.Infof("Parsing %s ...", options.InputFile)
		output, err := trace.ParseInputFile(options.InputFile)
		if err != nil {
			logrus.Errorf("couldn't parse input file: %v", err)
		} else {
			logrus.Infof("done ! Output file: %s", output)
		}
	}

	_ = trace.Stop()
	return nil
}

// wait stops the main goroutine until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
