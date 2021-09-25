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
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/Gui774ume/etrace/internal/btf"
	"github.com/sirupsen/logrus"
)

var (
	tracepointSyscallsPath         = "/sys/kernel/debug/tracing/events/syscalls/"
	tracepointSyscallFormatPattern = tracepointSyscallsPath + "sys_enter_%s/format"
	formatRegex                    = regexp.MustCompile(".*field:(.*);\toffset:(.*);\tsize:(.*);\tsigned:(.*);")
)

func (e *ETrace) prepareSyscallArgs() error {
	// load kernel BTF
	var err error
	e.kernelSpec, err = btf.LoadKernelSpec()
	if err != nil {
		return err
	}

	// list available syscall trace points
	syscalls, err := ioutil.ReadDir(tracepointSyscallsPath)
	if err != nil {
		return err
	}

	var fmtFile *os.File
	var syscallName string
	var fmtData []byte
	var splittedArgs []string

	for _, syscall := range syscalls {
		if !strings.HasPrefix(syscall.Name(), "sys_enter_") {
			continue
		}

		// read format file to retrieve arguments definition
		syscallName = strings.TrimPrefix(syscall.Name(), "sys_enter_")
		fmtFile, err = os.Open(fmt.Sprintf(tracepointSyscallFormatPattern, syscallName))
		if err != nil {
			logrus.Debugf("couldn't open format file for %s: %v", syscallName, err)
			continue
		}

		fmtData, err = ioutil.ReadAll(fmtFile)
		if err != nil {
			logrus.Debugf("couldn't read format file for %s: %v", syscallName, err)
			continue
		}

		// extract syscall arguments
		syscallFuncProto := SyscallDefinition{
			NR: ParseSyscallName(syscallName),
		}
		args := formatRegex.FindAllSubmatch(fmtData, -1)

		for i := 5; i < len(args); i++ {
			splittedArgs = strings.Split(string(args[i][1]), " ")
			arg := SyscallArgument{
				Name:       splittedArgs[len(splittedArgs)-1],
				Definition: strings.Join(splittedArgs[:len(splittedArgs)-1], " "),
			}
			arg.Size, err = strconv.Atoi(string(args[i][3]))
			if err != nil {
				arg.Size = 0
			}
			arg.ParseType()

			// try to resolve size using the kernel BTF
			if err = e.kernelSpec.FindType(arg.TypeName, arg.BTFType); err == nil {
				// update argument size
				arg.ResolveSizeFromBTFType()
			} else {
				// override the length of buffer with variable length
				if arg.TypeName == "void" || arg.TypeName == "char" {
					arg.Size = 0
					arg.BTFType = &btf.Int{
						Size:     MaxDataPerArg,
						Encoding: btf.Char,
					}

					// the size of the buffer can be determined by:
					//   - a trailing \x00
					//   - another syscall argument
					//   - the return value
					arg.ResolveDynamicSizeResolutionType(syscallFuncProto.NR, i-5, e.kernelSpec)
				} else {
					// the remaining unresolved types are integers. The value parsed in the trace point format is enough.
					intType := &btf.Int{
						Size: uint32(arg.Size),
					}
					if arg.TypeName == "int" {
						intType.Encoding = btf.Signed
					}
					arg.BTFType = intType
				}
			}
			syscallFuncProto.Arguments = append(syscallFuncProto.Arguments, arg)
		}

		e.syscallDefinitions[syscallFuncProto.NR] = syscallFuncProto
	}
	return nil
}

func (e *ETrace) pushSyscallDefinitions() error {
	var err error
	for nr, def := range e.syscallDefinitions {
		if err = e.syscallDefinitionsMap.Put(nr, def); err != nil {
			return err
		}
	}
	return nil
}
