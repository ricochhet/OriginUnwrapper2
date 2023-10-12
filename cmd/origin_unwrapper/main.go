package main

import (
	"bytes"
	"crypto/sha1"
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"os"

	"github.com/ricochhet/origin_unwrapper/pkg/origin_unwrapper"
	"github.com/ricochhet/origin_unwrapper/pkg/pefile"
)

func getOoaHash(data []byte) []byte {
	if len(data) < 0x3E {
		return nil
	}
	return data[0x2A:0x3E]
}

func main() {
	inputPathPtr := flag.String("input", "", "input path")
	outputPathPtr := flag.String("output", "", "output path")
	dlfKeyPtr := flag.String("key", "", "dlf key")
	versionPtr := flag.String("version", "", "hash version")
	getDlfKey := flag.String("dlf-path", "", "dlf path")
	addDllPtr := flag.Bool("add-dll", false, "true / false")
	flag.Parse()

	if len(*inputPathPtr) == 0 || len(*outputPathPtr) == 0 || len(*dlfKeyPtr) == 0 || len(*versionPtr) == 0 {
		fmt.Println("Error: not enough arguments specified")
		return
	}

	fileMap, err := pefile.Open(*inputPathPtr)
	if err != nil {
		fmt.Println(err)
		return
	}

	sectionsNum := len(fileMap.PE.Sections)
	sectionHeader := fileMap.PE.Sections[sectionsNum-1]

	if sectionHeader.Name != ".ooa" {
		fmt.Println("Error: invalid PE File! Section name is not '.ooa'")
		return
	}

	section := fileMap.Bytes[sectionHeader.Offset : sectionHeader.Offset+sectionHeader.Size]
	hash := getOoaHash(section)

	versionHash := sha1.New()
	versionHash.Write([]byte(*versionPtr))
	eq := bytes.Compare(hash, versionHash.Sum(nil)[:])
	if eq != 0 {
		fmt.Println("Error: hash version invalid")
		return
	}

	var sectionData pefile.Section
	sectionData, err = origin_unwrapper.Parse(section)
	if err != nil {
		fmt.Println(err)
		return
	}

	if sectionData.ImageBase != 0 {
		val := fileMap.PE.OptionalHeader.(*pe.OptionalHeader64).ImageBase == sectionData.ImageBase
		fmt.Printf("Assert: %t (sectionData.ImageBase != 0)\n", val)
	}

	if len(*getDlfKey) != 0 {
		var dlf []byte
		if len(os.Args) > 2 {
			data, err := os.ReadFile(*getDlfKey)
			if err == nil {
				dlf, err = origin_unwrapper.DecryptDLF(data)
				if err != nil {
					fmt.Println("Error: DecryptDLF()")
					return
				}
			}
		} else {
			dlf, err = origin_unwrapper.GetDLFAuto(*getDlfKey + sectionData.ContentID)
			if err != nil {
				fmt.Println("Error: GetDLFAuto()")
				return
			}
		}

		if len(dlf) == 0 {
			fmt.Println("Error: len(dlf) == 0")
			return
		}

		fmt.Printf("DLF: %s\n", string(dlf))
		dlfKey, err := origin_unwrapper.DecodeCipherTag(dlf)
		if dlfKey == nil {
			fmt.Println("Error: failed to get CipherKey from DLF!")
			return
		}
		if err != nil {
			fmt.Println("Error: DecodeCipherTag()")
			return
		}

		*dlfKeyPtr = string(dlfKey)
	}

	var newBytes []byte
	newBytes = append([]byte(nil), fileMap.Bytes[:]...)
	e_lfanew := binary.LittleEndian.Uint32(fileMap.Bytes[60:64])
	fileHeaderSize := uint32(24)

	for _, block := range sectionData.EncBlocks {
		var decryptHeader *pe.Section
		for _, s := range fileMap.PE.Sections {
			if s.VirtualAddress == block.VA {
				decryptHeader = *&s
				break
			}
		}

		if decryptHeader == nil {
			panic("(panic)Error: failed to find section for decryption!\n")
		}

		iv := make([]byte, 16)
		copy(iv, newBytes[decryptHeader.Offset-0x10:decryptHeader.Offset])
		err := origin_unwrapper.AESDecryptBase64(*dlfKeyPtr, iv, newBytes[decryptHeader.Offset:decryptHeader.Offset+decryptHeader.Size])
		if err != nil {
			panic(fmt.Errorf("(panic)Error: %s\n", err))
		}
		aesCBCPadding := []byte{0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10}
		if bytes.Equal(newBytes[decryptHeader.Offset+decryptHeader.Size-0x10:decryptHeader.Offset+decryptHeader.Size], aesCBCPadding) {
			copy(newBytes[decryptHeader.Offset+decryptHeader.Size-0x10:decryptHeader.Offset+decryptHeader.Size],
				make([]byte, 16))
		}
	}

	oepOff := e_lfanew + fileHeaderSize + 16
	binary.LittleEndian.PutUint32(newBytes[oepOff:oepOff+4], uint32(sectionData.OEP))

	if sectionData.ImportDir.VA != 0 && sectionData.ImportDir.Size != 0 {
		importDirOff := e_lfanew + fileHeaderSize + 120
		binary.LittleEndian.PutUint32(newBytes[importDirOff:importDirOff+4], sectionData.ImportDir.VA)
		binary.LittleEndian.PutUint32(newBytes[importDirOff+4:importDirOff+8], sectionData.ImportDir.Size)
	} else {
		fmt.Printf("Warning: did not fix ImportDir: %v\n", sectionData.ImportDir)
	}

	if sectionData.RelocDir.VA != 0 && sectionData.RelocDir.Size != 0 {
		relocDirOff := e_lfanew + fileHeaderSize + 152
		binary.LittleEndian.PutUint32(newBytes[relocDirOff:relocDirOff+4], sectionData.RelocDir.VA)
		binary.LittleEndian.PutUint32(newBytes[relocDirOff+4:relocDirOff+8], sectionData.RelocDir.Size)
	} else {
		fmt.Printf("Warning: did not fix Weird RelocDir: %v\n", sectionData.RelocDir)
	}

	if sectionData.IATDir.VA != 0 && sectionData.IATDir.Size != 0 {
		iatOff := e_lfanew + fileHeaderSize + 208
		binary.LittleEndian.PutUint32(newBytes[iatOff:iatOff+4], sectionData.IATDir.VA)
		binary.LittleEndian.PutUint32(newBytes[iatOff+4:iatOff+8], sectionData.IATDir.Size)
	} else {
		fmt.Printf("Warning: did not fix Weird IATDir: %v\n", sectionData.IATDir)
	}

	if err := os.WriteFile(*outputPathPtr, newBytes, os.ModePerm); err != nil {
		fmt.Println(err)
		return
	}

	if *addDllPtr {
		addDllToExe, err := pefile.Open(*outputPathPtr)
		if err != nil {
			fmt.Println(err)
			return
		}

		var dllEntries = []origin_unwrapper.DLLEntry{
			{
				DLL:   "anadius64",
				Names: []string{"anadius"},
			},
		}
		origin_unwrapper.AddDLLImports(addDllToExe, *sectionHeader, ".anadius", dllEntries, true)
		patchedExeBytes := append([]byte(nil), addDllToExe.Bytes[:]...)

		if err := os.WriteFile(*outputPathPtr, patchedExeBytes, os.ModePerm); err != nil {
			fmt.Println(err)
			return
		}
	}

	return
}
