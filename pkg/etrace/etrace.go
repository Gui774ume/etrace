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
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/etrace/internal/btf"
	"github.com/Gui774ume/etrace/pkg/ringbuf"
)

var eventZero = NewSyscallEvent()

// ETrace is the main ETrace structure
type ETrace struct {
	handleEvent func(data []byte)
	options     Options
	inputFile   *os.File
	dumpFile    *os.File
	jsonEncoder *json.Encoder

	ctx        context.Context
	cancelFunc context.CancelFunc
	wg         *sync.WaitGroup

	manager        *manager.Manager
	managerOptions manager.Options
	startTime      time.Time

	kernelSpec            *btf.Spec
	SyscallDefinitions    map[Syscall]SyscallDefinition
	syscallDefinitionsMap *ebpf.Map
	eventsSyncMap         *ebpf.Map
	eventsStatsMap        *ebpf.Map
	syscallFilterMap      *ebpf.Map
	commFilterMap         *ebpf.Map

	reader       *ringbuf.Reader
	event        *SyscallEvent
	timeResolver *TimeResolver
	numCPU       int

	// DumpFile is the output file
	DumpFile string
}

// NewETrace creates a new ETrace instance
func NewETrace(options Options) (*ETrace, error) {
	var err error

	if err = options.IsValid(); err != nil {
		return nil, err
	}

	e := &ETrace{
		wg:                 &sync.WaitGroup{},
		options:            options,
		handleEvent:        options.EventHandler,
		SyscallDefinitions: make(map[Syscall]SyscallDefinition),
		event:              NewSyscallEvent(),
	}
	if e.handleEvent == nil {
		e.handleEvent = e.defaultEventHandler
	} else {
		e.options.hasCustomEventHandler = true
	}

	var pattern string
	if options.RawDump {
		pattern = "etrace-*.raw"
	} else if options.JSONDump {
		pattern = "etrace-*.json"
	}
	if len(pattern) > 0 {
		e.dumpFile, err = ioutil.TempFile("/tmp", pattern)
		if err != nil {
			return nil, err
		}
		e.DumpFile = e.dumpFile.Name()
		if err = os.Chmod(e.DumpFile, 0777); err != nil {
			return nil, err
		}

		if options.JSONDump {
			e.jsonEncoder = json.NewEncoder(e.dumpFile)
		}
	}

	e.timeResolver, err = NewTimeResolver()
	if err != nil {
		return nil, err
	}

	e.numCPU, err = NumCPU()
	if err != nil {
		return nil, err
	}
	e.ctx, e.cancelFunc = context.WithCancel(context.Background())

	if err := e.prepareSyscallArgs(); err != nil {
		return nil, errors.Wrap(err, "couldn't prepare syscall arguments")
	}
	return e, nil
}

// Start hooks on the requested symbols and begins tracing
func (e *ETrace) Start() error {
	if e.options.ShouldActivateProbes() {
		if err := e.startManager(); err != nil {
			return err
		}

		if err := e.pushSyscallDefinitions(); err != nil {
			return errors.Wrap(err, "couldn't push syscall definitions to the kernel")
		}

		if err := e.pushFilters(); err != nil {
			return errors.Wrap(err, "couldn't push filters to the kernel")
		}
	}
	return nil
}

// ParseInputFile parses a raw input file into a JSON output file
func (e *ETrace) ParseInputFile(inputFile string) (string, error) {
	var err error
	e.dumpFile, err = ioutil.TempFile("/tmp", "etrace-*.json")
	if err != nil {
		return "", err
	}
	e.DumpFile = e.dumpFile.Name()
	if err = os.Chmod(e.DumpFile, 0777); err != nil {
		return "", err
	}
	e.jsonEncoder = json.NewEncoder(e.dumpFile)

	// read input file
	e.inputFile, err = os.Open(inputFile)
	if err != nil {
		return "", fmt.Errorf("couldn't open input file %s: %w", inputFile, err)
	}

	var sizeB [2]byte
	var done bool
	var data []byte
	for !done {
		if _, err = e.inputFile.Read(sizeB[:]); err != nil {
			break
		}

		data = make([]byte, ByteOrder.Uint16(sizeB[:]))
		if _, err = e.inputFile.Read(data); err != nil {
			break
		}

		event = e.zeroEvent()
		if err = e.ParseData(data, event); err != nil {
			logrus.Debugf("failed to parse event: %s", err)
			continue
		}

		if err = e.jsonEncoder.Encode(event); err != nil {
			logrus.Debugf("failed to encode event: %s", err)
			continue
		}
	}

	return e.DumpFile, nil
}

// Stop shuts down ETrace
func (e *ETrace) Stop() error {
	if e.options.ShouldActivateProbes() {
		if e.manager == nil {
			// nothing to stop, return
			return nil
		}

		// stop writting to the ring buffer
		syncKey := uint32(0)
		stop := uint32(1)
		_ = e.eventsSyncMap.Put(syncKey, stop)

	}

	e.cancelFunc()

	if e.options.ShouldActivateProbes() {
		if e.reader != nil {
			_ = e.reader.Close()
		}
		e.wg.Wait()
		if e.dumpFile != nil {
			_ = e.dumpFile.Close()
		}

		// dump events stats
		if e.options.Stats {
			if err := e.dumpEventsStats(); err != nil {
				return err
			}
		}

		if err := e.manager.Stop(manager.CleanAll); err != nil {
			return fmt.Errorf("couldn't stop manager: %w", err)
		}
	}
	return nil
}

type EventStats struct {
	Lost uint64
	Sent uint64
}

func (e *ETrace) dumpEventsStats() error {
	stats := make([]EventStats, e.numCPU)
	var syscall Syscall
	var iterSent uint64
	var iterLost uint64
	var totalSent uint64
	var totalLoast uint64

	// loop through all the values of the stats map
	logrus.Infoln()
	logrus.Infof("%24s\t\t|\t\tSent\t\t|\t\tLost", "Syscall Name")
	iterator := e.eventsStatsMap.Iterate()
	for iterator.Next(&syscall, &stats) {
		if syscall == SysLastSyscall {
			break
		}
		iterSent = 0
		iterLost = 0
		for _, counters := range stats {
			iterSent += counters.Sent
			iterLost += counters.Lost
		}

		if iterSent > 0 || iterLost > 0 {
			logrus.Infof("%24s\t\t|\t\t%d\t\t|\t\t%d", syscall, iterSent, iterLost)
			totalSent += iterSent
			totalLoast += iterLost
		}
	}
	if err := iterator.Err(); err != nil {
		logrus.Warnf("couldn't dump events stats map: %v", err)
	}
	logrus.Infoln()
	logrus.Infof("Total events: %d", totalSent)
	logrus.Infof("Total lost: %d", totalLoast)
	return nil
}

func (e *ETrace) pushFilters() error {
	var err error
	filter := uint32(1)

	if len(e.options.CommFilters) > 0 {
		for _, comm := range e.options.CommFilters {
			commB := make([]byte, 16)
			copy(commB[:], comm)
			err = e.commFilterMap.Put(commB, filter)
			if err != nil {
				return errors.Wrapf(err, "couldn't push comm filter for \"%s\"", comm)
			}
		}
	}

	if len(e.options.SyscallFilters) > 0 {
		for _, s := range e.options.SyscallFilters {
			err = e.syscallFilterMap.Put(s, filter)
			if err != nil {
				return errors.Wrapf(err, "couldn't push syscall filter for \"%s\"", s)
			}
		}
	}

	if e.options.Stats && !e.options.SendEventsToUserSpace() {
		syncKey := uint32(0)
		ignore := uint32(2)
		_ = e.eventsSyncMap.Put(syncKey, ignore)
	}

	return nil
}

func (e *ETrace) zeroEvent() *SyscallEvent {
	*e.event = *eventZero
	return e.event
}

// sizeB is used to store and write the size of the bytes buffer received from the ring buffer
var sizeB [2]byte
var jsonData []byte
var newLine = []byte("\n")
var event *SyscallEvent

func (e *ETrace) defaultEventHandler(data []byte) {
	var err error
	jsonData = nil

	if e.options.RawDump {
		ByteOrder.PutUint16(sizeB[:], uint16(len(data)))
		_, err = e.dumpFile.Write(sizeB[:])
		if err != nil {
			logrus.Errorf("failed to write buffer size: %s", err)
			return
		}
		_, err = e.dumpFile.Write(data)
		if err != nil {
			logrus.Errorf("failed to write buffer: %s", err)
			return
		}
		return
	}

	if e.options.JSONDump || e.options.Stdout {
		event = e.zeroEvent()

		if err = e.ParseData(data, event); err != nil {
			logrus.Errorln(err)
		}

		if e.options.JSONDump {
			if err = e.jsonEncoder.Encode(event); err != nil {
				logrus.Errorln(err)
			}
		} else if e.options.Stdout {
			fmt.Printf("%s\n", event.String(e.options.BytesShown))
		}
	}
}

// ParseData parses a SyscallEvent from a raw bytes array
func (e *ETrace) ParseData(data []byte, event *SyscallEvent) error {
	// parse syscall type
	read, err := event.Syscall.UnmarshalSyscall(data)
	if err != nil {
		return fmt.Errorf("failed to decode syscall type: %w", err)
	}

	// resolve arguments definition
	syscallDefinition, ok := e.SyscallDefinitions[event.Syscall]
	if ok {
		for i := range syscallDefinition.Arguments {
			event.Args[i] = SyscallArgumentValue{
				Argument: &syscallDefinition.Arguments[i],
			}
		}
	} else {
		return fmt.Errorf("couldn't find the syscall definition of %s", event.Syscall)
	}

	// unmarshal
	err = event.UnmarshalBinary(data, read, e)
	if err != nil {
		return fmt.Errorf("failed to decode event: %w", err)
	}

	return nil
}
