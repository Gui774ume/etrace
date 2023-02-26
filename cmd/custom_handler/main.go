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

package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/etrace/pkg/etrace"
)

// et is the global etrace tracer
var et *etrace.ETrace

// eventZero is used to reset the event used for parsing in a memory efficient way
var eventZero = etrace.NewSyscallEvent()

// event is used to parse events
var event = etrace.NewSyscallEvent()

// zeroEvent provides an empty event
func zeroEvent() {
	*event = *eventZero
}

func main() {
	// Set log level
	logrus.SetLevel(logrus.TraceLevel)

	// create a new ETrace instance
	var err error
	et, err = etrace.NewETrace(etrace.Options{
		EventHandler: myCustomEventHandler,
	})
	if err != nil {
		logrus.Errorf("couldn't instantiate etrace: %v\n", err)
		return
	}

	// start ETrace
	if err = et.Start(); err != nil {
		logrus.Errorf("couldn't start etrace: %v\n", err)
		return
	}
	logrus.Infoln("Tracing started ... (Ctrl + C to stop)\n")

	wait()

	if err = et.Stop(); err != nil {
		logrus.Errorf("couldn't stop etrace: %v\n", err)
	}
}

// wait stops the main goroutine until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}

func myCustomEventHandler(data []byte) {
	// reset event
	zeroEvent()

	// parse syscall type
	read, err := event.Syscall.UnmarshalSyscall(data)
	if err != nil {
		logrus.Errorf("failed to decode syscall type: %v", err)
		return
	}

	// find arguments definition
	syscallDefinition, ok := et.SyscallDefinitions[event.Syscall]
	if ok {
		for i := range syscallDefinition.Arguments {
			event.Args[i] = etrace.SyscallArgumentValue{
				Argument: &syscallDefinition.Arguments[i],
			}
		}
	} else {
		logrus.Errorf("couldn't find the syscall definition of %s", event.Syscall)
		return
	}

	// parse the binary data according to the syscall definition
	err = event.UnmarshalBinary(data, read, et)
	if err != nil {
		logrus.Errorf("failed to decode event: %v", err)
		return
	}

	// print the output to the screen
	fmt.Printf("%s\n", event.String(50))
}
