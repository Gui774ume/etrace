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
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/Gui774ume/etrace/internal/btf"

	"github.com/pkg/errors"
)

const (
	CgroupNameLength  = 72
	TaskCommLength    = 16
	CgroupSubSysCount = 13
)

type CgroupContext struct {
	SubsystemID uint32 `json:"subsystem_id"`
	StateID     uint32 `json:"state_id"`
	Name        string `json:"name"`
}

func (cc *CgroupContext) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 8+CgroupNameLength {
		return 0, errors.Wrapf(ErrNotEnoughData, "parsing CgroupContext, got len %d, needed %d", len(data), 8+CgroupNameLength)
	}
	cc.SubsystemID = ByteOrder.Uint32(data[0:4])
	cc.StateID = ByteOrder.Uint32(data[4:8])
	cc.Name = string(bytes.Trim(data[8:8+CgroupNameLength], "\x00"))
	return 8 + CgroupNameLength, nil
}

type CredentialsContext struct {
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
	SUID           uint32 `json:"suid"`
	SGID           uint32 `json:"sgid"`
	EUID           uint32 `json:"euid"`
	EGID           uint32 `json:"egid"`
	FSUID          uint32 `json:"fsuid"`
	FSGID          uint32 `json:"fsgid"`
	SecureBits     uint32 `json:"secure_bits"`
	CapInheritable uint64 `json:"cap_inheritable"`
	CapPermitted   uint64 `json:"cap_permitted"`
	CapEffective   uint64 `json:"cap_effective"`
	CapBSET        uint64 `json:"cap_bset"`
	CapAmbiant     uint64 `json:"cap_ambiant"`
}

func (cc *CredentialsContext) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 80 {
		return 0, errors.Wrapf(ErrNotEnoughData, "parsing CredentialsContext, got len %d, needed 80", len(data))
	}
	cc.UID = ByteOrder.Uint32(data[:4])
	cc.GID = ByteOrder.Uint32(data[4:8])
	cc.SUID = ByteOrder.Uint32(data[8:12])
	cc.SGID = ByteOrder.Uint32(data[12:16])
	cc.EUID = ByteOrder.Uint32(data[16:20])
	cc.EGID = ByteOrder.Uint32(data[20:24])
	cc.FSUID = ByteOrder.Uint32(data[24:28])
	cc.FSGID = ByteOrder.Uint32(data[28:32])
	cc.SecureBits = ByteOrder.Uint32(data[32:36])
	// padding
	cc.CapInheritable = ByteOrder.Uint64(data[40:48])
	cc.CapPermitted = ByteOrder.Uint64(data[48:56])
	cc.CapEffective = ByteOrder.Uint64(data[56:64])
	cc.CapBSET = ByteOrder.Uint64(data[64:72])
	cc.CapAmbiant = ByteOrder.Uint64(data[72:80])
	return 80, nil
}

type NamespaceContext struct {
	CgroupNamespace uint32 `json:"cgroup_namespace"`
	IPCNamespace    uint32 `json:"ipc_namespace"`
	NetNamespace    uint32 `json:"net_namespace"`
	MntNamespace    uint32 `json:"mnt_namespace"`
	PIDNamespace    uint32 `json:"pid_namespace"`
	TimeNamespace   uint32 `json:"time_namespace"`
	UserNamespace   uint32 `json:"user_namespace"`
	UTSNamespace    uint32 `json:"uts_namespace"`
}

func (nc *NamespaceContext) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 32 {
		return 0, errors.Wrapf(ErrNotEnoughData, "parsing NamespaceContext, got len %d, needed 32", len(data))
	}
	nc.CgroupNamespace = ByteOrder.Uint32(data[:4])
	nc.IPCNamespace = ByteOrder.Uint32(data[4:8])
	nc.NetNamespace = ByteOrder.Uint32(data[8:12])
	nc.MntNamespace = ByteOrder.Uint32(data[12:16])
	nc.PIDNamespace = ByteOrder.Uint32(data[16:20])
	nc.TimeNamespace = ByteOrder.Uint32(data[20:24])
	nc.UserNamespace = ByteOrder.Uint32(data[24:28])
	nc.UTSNamespace = ByteOrder.Uint32(data[28:32])
	return 32, nil
}

type ProcessContext struct {
	Cgroups          [CgroupSubSysCount]CgroupContext `json:"cgroups"`
	NamespaceContext NamespaceContext                 `json:"namespace_context"`
	Credentials      CredentialsContext               `json:"credentials"`
	Comm             string                           `json:"comm"`
}

func (pc *ProcessContext) UnmarshalBinary(data []byte) (int, error) {
	var cursor, read int
	var err error

	read, err = pc.NamespaceContext.UnmarshalBinary(data[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += read

	read, err = pc.Credentials.UnmarshalBinary(data[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += read

	if len(data[cursor:]) < TaskCommLength {
		return 0, errors.Wrapf(err, "parsing ProcessContext.Comm: got len %d, needed %d", len(data[cursor:]), TaskCommLength)
	}
	pc.Comm = string(bytes.Trim(data[cursor:cursor+TaskCommLength], "\x00"))
	cursor += TaskCommLength

	for i := 0; i < CgroupSubSysCount; i++ {
		read, err = pc.Cgroups[i].UnmarshalBinary(data[cursor:])
		if err != nil {
			return 0, err
		}
		cursor += read
	}

	return cursor, nil
}

type ParsedSyscallArgumentValue struct {
	Type       string                                  `json:"type"`
	Size       int                                     `json:"size"`
	Data       []byte                                  `json:"data,omitempty"`
	ParsedData interface{}                             `json:"parsed_data,omitempty"`
	Members    []map[string]ParsedSyscallArgumentValue `json:"members,omitempty"`
}

func (psav ParsedSyscallArgumentValue) String(name string, sav *SyscallArgumentValue, bytesShown int) string {
	t := psav.Type
	if sav != nil {
		t = sav.argument.Definition
	}
	output := fmt.Sprintf("%s %s: ", t, name)
	if psav.ParsedData != nil {
		output += fmt.Sprint(psav.ParsedData)
	} else if len(psav.Members) > 0 {
		output += "{"
		for i, arg := range psav.Members {
			for name, val := range arg {
				if i > 0 {
					output += ", "
				}
				output += val.String(name, nil, bytesShown)
			}
		}
		output += "}"
	} else {
		end := bytesShown
		if end > len(psav.Data) {
			end = len(psav.Data)
		}
		if len(psav.Data) > 0 {
			output += fmt.Sprintf("0x%x...", psav.Data[:end])
		} else {
			output += "NULL"
		}
	}
	return output
}

type SyscallArgumentValue struct {
	argument   *SyscallArgument
	parsedData *ParsedSyscallArgumentValue
	data       []byte
}

func parseInt(data []byte, isSigned bool) interface{} {
	if isSigned {
		switch len(data) {
		case 1:
			return int8(data[0])
		case 2:
			val := ByteOrder.Uint16(data[0:2])
			return int16(val)
		case 4:
			val := ByteOrder.Uint32(data[0:4])
			return int32(val)
		case 8:
			val := ByteOrder.Uint64(data[0:8])
			return int64(val)
		}
	} else {
		switch len(data) {
		case 1:
			return data[0]
		case 2:
			return ByteOrder.Uint16(data[0:2])
		case 4:
			return ByteOrder.Uint32(data[0:4])
		case 8:
			return ByteOrder.Uint64(data[0:8])
		}
	}
	return nil
}

func newParsedSyscallArgumentValue(t btf.Type, data []byte, sav *SyscallArgumentValue) ParsedSyscallArgumentValue {
	var output ParsedSyscallArgumentValue
	switch reflect.TypeOf(t) {
	case reflect.TypeOf(&btf.Void{}):
		output.Type = "void"
		output.Size = len(data)
		if output.Size > 0 {
			output.Data = data
		}
	case reflect.TypeOf(&btf.Int{}):
		i := t.(*btf.Int)
		if i.Encoding&btf.Signed == btf.Signed {
			output.Type = "int"
		} else if i.Encoding&btf.Char == btf.Char {
			output.Type = "char"
		} else {
			output.Type = "uint"
		}
		var resizedData []byte
		output.Size = int(i.Size)
		if len(data) >= output.Size {
			resizedData = data[0:output.Size]
		} else {
			output.Size = len(data)
			resizedData = data
		}
		if output.Size > 0 {
			output.Data = resizedData
			if i.Encoding&btf.Char == btf.Char {
				dataStr := bytes.NewBuffer(bytes.Trim(resizedData, "\x00")).String()
				// actual strings should have the same size in bytes and in their ASCII representation
				// (the -1 accounts for the trailing \x00)
				if len(dataStr) == len(resizedData) || len(dataStr) == len(resizedData)-1 {
					output.ParsedData = dataStr
				}
			} else {
				output.ParsedData = parseInt(resizedData, i.Encoding&btf.Signed == btf.Signed)
			}
		}
	case reflect.TypeOf(&btf.Struct{}):
		s := t.(*btf.Struct)
		output.Type = fmt.Sprintf("struct %s", string(s.Name))
		output.Size = int(s.Size)
		if len(data) >= output.Size {
			if output.Size > 0 {
				output.Data = data[0:output.Size]
			}
		} else {
			output.Size = len(data)
			if output.Size > 0 {
				output.Data = data
			}
		}

		var end int
		dataLen := len(data)
		for i, member := range s.Members {
			if i+1 < len(s.Members) {
				end = int(s.Members[i+1].Offset / 8)
			} else {
				end = dataLen
			}
			// make sure the entry is complete before parsing it (it could have been truncated)
			if dataLen >= int(member.Offset/8) && dataLen >= end {
				output.Members = append(output.Members, map[string]ParsedSyscallArgumentValue{
					string(member.Name): newParsedSyscallArgumentValue(member.Type, data[member.Offset/8:end], nil),
				})
			} else {
				// ignore truncated entries
				break
			}
		}
	case reflect.TypeOf(&btf.Pointer{}):
		p := t.(*btf.Pointer)
		// do not follow the pointer if the data left is simply a pointer
		if len(data) <= 8 {
			output.Type = "void *"
			output.Size = len(data)
			output.Data = data
		} else {
			output = newParsedSyscallArgumentValue(p.Target, data, nil)
		}
	case reflect.TypeOf(&btf.Array{}):
		a := t.(*btf.Array)
		output.Type = "array"
		output.Size = len(data)
		if output.Size > 0 {
			output.Data = data
		}

		if a.Nelems > 0 {
			elemSize := output.Size / int(a.Nelems)
			dataLen := len(data)
			for i := 0; i < int(a.Nelems); i++ {
				if dataLen >= (i+1)*elemSize {
					output.Members = append(output.Members, map[string]ParsedSyscallArgumentValue{
						fmt.Sprintf("%d", i): newParsedSyscallArgumentValue(a.Type, data[i*elemSize:(i+1)*elemSize], nil),
					})
				} else {
					// ignore truncated entries
					break
				}
			}
		}
	case reflect.TypeOf(&btf.Typedef{}):
		td := t.(*btf.Typedef)
		output = newParsedSyscallArgumentValue(td.Type, data, nil)
	case reflect.TypeOf(&btf.Volatile{}):
		v := t.(*btf.Volatile)
		output = newParsedSyscallArgumentValue(v.Type, data, nil)
	case reflect.TypeOf(&btf.Const{}):
		c := t.(*btf.Const)
		output = newParsedSyscallArgumentValue(c.Type, data, nil)
	case reflect.TypeOf(&btf.Restrict{}):
		r := t.(*btf.Restrict)
		output = newParsedSyscallArgumentValue(r.Type, data, nil)
	default:
		output.Size = len(data)
		if output.Size > 0 {
			output.Data = data
		}
	}

	// override type and typename if this is the top level entry
	if sav != nil {
		output.Type = sav.argument.Definition
	}

	return output
}

func (sav SyscallArgumentValue) Parse() *ParsedSyscallArgumentValue {
	if sav.parsedData == nil {
		parsedValue := newParsedSyscallArgumentValue(sav.argument.BTFType, sav.data, &sav)
		sav.parsedData = &parsedValue
	}
	return sav.parsedData
}

func (sav SyscallArgumentValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(sav.Parse())
}

type SyscallArgumentsList [6]SyscallArgumentValue

func (sal SyscallArgumentsList) MarshalJSON() ([]byte, error) {
	var output []map[string]SyscallArgumentValue
	for _, arg := range sal {
		if arg.argument != nil {
			output = append(output, map[string]SyscallArgumentValue{
				arg.argument.Name: arg,
			})
		}
	}
	return json.Marshal(output)
}

func (sal SyscallArgumentsList) String(bytesShown int) string {
	var output string
	for i, arg := range sal {
		if arg.argument != nil {
			if i >= 1 {
				output += ", "
			}
			output += arg.Parse().String(arg.argument.Name, &arg, bytesShown)
		}
	}
	return output
}

type SyscallEvent struct {
	Syscall             Syscall        `json:"syscall"`
	Ret                 uint64         `json:"ret"`
	Timestamp           time.Time      `json:"timestamp"`
	PID                 uint32         `json:"pid"`
	TID                 uint32         `json:"tid"`
	EntryProcessContext ProcessContext `json:"entry_process_context"`
	ExitProcessContext  ProcessContext `json:"exit_process_context"`

	Args    SyscallArgumentsList `json:"args"`
	ArgsRaw []byte               `json:"args_raw"`
}

func (se *SyscallEvent) String(bytesShown int) string {
	return fmt.Sprintf("%s(%d) | %s(%s) = %d", se.EntryProcessContext.Comm, se.TID, se.Syscall, se.Args.String(bytesShown), int64(se.Ret))
}

// var brokenSyscalls = make(map[Syscall]int)

func (se *SyscallEvent) unmarshalBinary(data []byte, read int, e *ETrace) error {
	var err error
	cursor := read

	if len(data[cursor:]) < 28 {
		return errors.Wrapf(err, "parsing Ret, Timestamp, PID and TID: got len %d, needed 28", len(data[cursor:]))
	}
	se.PID = ByteOrder.Uint32(data[cursor : cursor+4])
	se.TID = ByteOrder.Uint32(data[cursor+4 : cursor+8])
	// padding
	se.Ret = ByteOrder.Uint64(data[cursor+12 : cursor+20])
	se.Timestamp = e.timeResolver.ResolveMonotonicTimestamp(ByteOrder.Uint64(data[cursor+20 : cursor+28]))
	cursor += 28

	read, err = se.EntryProcessContext.UnmarshalBinary(data[cursor:])
	if err != nil {
		return err
	}
	cursor += read

	read, err = se.ExitProcessContext.UnmarshalBinary(data[cursor:])
	if err != nil {
		return err
	}
	cursor += read

	// parse arguments
	se.ArgsRaw = data[cursor:]

	var size int
	for i := 0; i < 6; i++ {
		if len(data[cursor:]) < 4 {
			break
		}
		size = int(int32(ByteOrder.Uint32(data[cursor : cursor+4])))
		cursor += 4
		if cursor+size > len(data) {
			size = len(data) - cursor
		}
		if size > 0 {
			se.Args[i].data = make([]byte, size)
			copy(se.Args[i].data[:], data[cursor:cursor+size])
			cursor += size
			_ = se.Args[i].Parse()
		} else {
			// Two options:
			//  - the syscall definition is broken and there is something wrong with the computed BTF data
			//  - the parameter was not provided to the syscall (this is an optional parameter)
			//
			// brokenSyscalls[se.Syscall] += 1
		}
	}
	return nil
}
