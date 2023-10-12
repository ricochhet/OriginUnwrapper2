package pefile

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
)

// COFFHeader
// 0x50, 0x45 = PE
// COFF_START_BYTES_LEN == len(COFF_START_BYTES)
var COFF_START_BYTES = []byte{0x50, 0x45, 0x00, 0x00}

const COFF_START_BYTES_LEN = 4
const COFF_HEADER_SIZE = 20

// OptionalHeader64
// https://github.com/golang/go/blob/master/src/debug/pe/pe.go
// uint byte size of OptionalHeader64 without magic mumber(2 bytes) or data directory(128 bytes)
// OptionalHeader64 size is 240
// (110)
var OH64_BYTE_SIZE = binary.Size(JmpOptionalHeader64{})

// DataDirectory
// 16 entries * 8 bytes / entry
const DD_SIZE = 128
const DD_ENTRY_SIZE = 8

// SectionHeader32
// https://github.com/golang/go/blob/master/src/debug/pe/section.go
// uint byte size of SectionHeader32 without name(8 bytes) or characteristics(4 bytes)
// (28)
var SH32_SIZE = binary.Size(JmpSectionHeader32{})

const SH32_ENTRY_SIZE = 64
const SH32_NAME_SIZE = 8
const SH32_CHARACTERISTICS_SIZE = 4

// Data structure
type Data struct {
	Bytes []byte
	PE    pe.File
}

// Section structure (.ooa)
type Section struct {
	ContentID   string
	OEP         uint64
	EncBlocks   []EncBlock
	ImageBase   uint64
	SizeOfImage uint32
	ImportDir   DataDir
	IATDir      DataDir
	RelocDir    DataDir
}

// Import structure (.ooa)
type Import struct {
	Characteristics uint32
	Timedatestamp   uint32
	ForwarderChain  uint32
	Name            uint32
	FThunk          uint32
}

// Thunk structure (.ooa)
type Thunk struct {
	Function uint32
	DataAddr uint32
}

// DataDir structure (.ooa)
type DataDir struct {
	VA   uint32
	Size uint32
}

// EncBlock structure (.ooa)
type EncBlock struct {
	VA          uint32
	RawSize     uint32
	VirtualSize uint32
	Unk         uint32
	CRC         uint32
	Unk2        uint32
	CRC2        uint32
	Pad         uint32
	FileOffset  uint32
	Pad2        uint64
	Pad3        uint32
}

type JmpOptionalHeader64 struct {
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

type JmpSectionHeader32 struct {
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
}

func Open(path string) (*Data, error) {
	m := new(Data)

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	ff, err := pe.NewFile(f)
	ra, err := io.ReadAll(f)

	if err != nil {
		f.Close()
		return nil, err
	}

	m.Bytes = ra
	m.PE = *ff
	return m, nil
}

func WriteBytes(bytes []byte, offset int, replace []byte) error {
	if offset < 0 || offset+len(replace) > len(bytes) {
		return fmt.Errorf("Error: invalid offset or byte range\n")
	}

	copy(bytes[offset:], replace)
	return nil
}

func ReadCOFFHeaderOffset(bytes []byte) (int, error) {
	offset, err := FindBytes(bytes, COFF_START_BYTES)
	if err != nil {
		return -1, err
	}

	return offset, nil
}

func ReadDDBytes(bytes []byte) ([]byte, error) {
	offset, err := ReadCOFFHeaderOffset(bytes)
	if err != nil {
		return nil, err
	}

	return bytes[offset+COFF_START_BYTES_LEN+COFF_HEADER_SIZE+OH64_BYTE_SIZE : offset+COFF_START_BYTES_LEN+COFF_HEADER_SIZE+OH64_BYTE_SIZE+DD_SIZE], nil
}

func ReadDDEntryOffset(bytes []byte, entryVirtualAddress uint32, entrySize uint32) (int, error) {
	dd, err := ReadDDBytes(bytes)
	if err != nil {
		return -1, err
	}

	entryBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(entryBytes[:4], entryVirtualAddress)
	binary.LittleEndian.PutUint32(entryBytes[4:], entrySize)

	rva, err := FindBytes(dd, entryBytes)
	if err != nil || rva == -1 {
		log.Fatal(err)
		return -1, err
	}

	offset, err := ReadCOFFHeaderOffset(bytes)
	if err != nil {
		return -1, err
	}
	return offset + COFF_START_BYTES_LEN + COFF_HEADER_SIZE + OH64_BYTE_SIZE + rva, nil
}

func ReadSHSize(file pe.File) (int, error) {
	sections := len(file.Sections)
	size := sections * SH32_ENTRY_SIZE

	if size == 0 {
		return -1, fmt.Errorf("Error: ReadSHSize()\n")
	}
	return size, nil
}

func ReadSHBytes(bytes []byte, shSize int) ([]byte, error) {
	offset, err := ReadCOFFHeaderOffset(bytes)
	if err != nil {
		return nil, err
	}

	return bytes[offset+COFF_START_BYTES_LEN+COFF_HEADER_SIZE+OH64_BYTE_SIZE+DD_SIZE : offset+COFF_START_BYTES_LEN+COFF_HEADER_SIZE+OH64_BYTE_SIZE+DD_SIZE+shSize], nil
}

func ReadSHEntryOffset(bytes []byte, address int) (int, error) {
	offset, err := ReadCOFFHeaderOffset(bytes)
	if err != nil {
		return -1, err
	}

	return offset + COFF_START_BYTES_LEN + COFF_HEADER_SIZE + OH64_BYTE_SIZE + DD_SIZE + address, nil
}

func ReadSectionBytes(file *Data, sectionVirtualAddress uint32, sectionSize uint32) ([]byte, error) {
	var section *pe.Section
	for _, s := range file.PE.Sections {
		if sectionVirtualAddress >= s.VirtualAddress && sectionVirtualAddress < s.VirtualAddress+s.Size {
			section = s
			break
		}
	}

	if section == nil {
		return nil, fmt.Errorf("Error: ReadSectionBytes()\n")
	}

	offset := sectionVirtualAddress - section.VirtualAddress + section.Offset
	bytes := file.Bytes[offset : offset+sectionSize]
	return bytes, nil
}

func ReadImport(reader io.Reader) Import {
	var importData Import
	binary.Read(reader, binary.LittleEndian, &importData)
	return importData
}

func ReadThunk(reader io.Reader) Thunk {
	var thunkData Thunk
	binary.Read(reader, binary.LittleEndian, &thunkData)
	return thunkData
}

func ReadDataDir(reader io.Reader) DataDir {
	var dataDir DataDir
	binary.Read(reader, binary.LittleEndian, &dataDir)
	return dataDir
}

func ReadEncBlock(reader io.Reader) EncBlock {
	var encBlock EncBlock
	binary.Read(reader, binary.LittleEndian, &encBlock)
	return encBlock
}

func FindBytes(src []byte, dst []byte) (int, error) {
	for i := 0; i < len(src)-len(dst)+1; i++ {
		if match(src[i:i+len(dst)], dst) {
			return i, nil
		}
	}
	return -1, fmt.Errorf("Error: FindBytes()\n")
}

func PadBytes(bytes []byte, size int) []byte {
	if len(bytes) < size {
		paddingSize := size - len(bytes)
		padding := make([]byte, paddingSize)
		return append(bytes, padding...)
	}

	return bytes
}

func match(src []byte, dst []byte) bool {
	for i := range dst {
		if src[i] != dst[i] {
			return false
		}
	}
	return true
}
