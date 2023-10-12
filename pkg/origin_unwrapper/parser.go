package origin_unwrapper

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
	"unsafe"

	"github.com/ricochhet/origin_unwrapper/pkg/pefile"
)

func extractStringFromData(data []byte, start, end int) string {
	var contentID string
	if end > len(data) {
		end = len(data)
	}

	rawSlice := data[start:end]
	u16Slice := ((*[1 << 30]uint16)(unsafe.Pointer(&rawSlice[0])))[:len(rawSlice)/2]

	nullIndex := -1
	for i, c := range u16Slice {
		if c == 0 {
			nullIndex = i
			break
		}
	}

	if nullIndex != -1 {
		contentID = string(utf16.Decode(u16Slice[:nullIndex]))
	} else {
		contentID = string(utf16.Decode(u16Slice))
	}

	return contentID
}

func Parse(data []byte) (pefile.Section, error) {
	contentId := extractStringFromData(data, 0x42, 0x240)
	reader := bytes.NewReader(data)
	reader.Seek(0x242, io.SeekStart)

	for {
		var importData pefile.Import
		if err := binary.Read(reader, binary.LittleEndian, &importData); err != nil {
			break
		}

		if importData.Characteristics == 0 {
			break
		}
	}

	for {
		var iatData pefile.Thunk
		if err := binary.Read(reader, binary.LittleEndian, &iatData); err != nil {
			break
		}

		if iatData.Function == 0 {
			break
		}
	}

	for {
		var originalData pefile.Thunk
		if err := binary.Read(reader, binary.LittleEndian, &originalData); err != nil {
			break
		}

		if originalData.Function == 0 {
			break
		}
	}

	reader.Seek(72, io.SeekCurrent)
	var relocMaxSize uint32
	if err := binary.Read(reader, binary.LittleEndian, &relocMaxSize); err != nil {
		return pefile.Section{}, fmt.Errorf("Error: relocMaxSize %w", err)
	}
	var relocNewSize uint32
	if err := binary.Read(reader, binary.LittleEndian, &relocNewSize); err != nil {
		return pefile.Section{}, fmt.Errorf("Error: relocNewSize %w", err)
	}
	reader.Seek(int64(relocMaxSize), io.SeekCurrent)

	var tls uint32
	if err := binary.Read(reader, binary.LittleEndian, &tls); err != nil {
		return pefile.Section{}, fmt.Errorf("Error: tls %w", err)
	}
	var tlsCallback uint32
	if err := binary.Read(reader, binary.LittleEndian, &tlsCallback); err != nil {
		return pefile.Section{}, fmt.Errorf("Error: tlsCallback %w", err)
	}
	var tlsFirstCallback uint64
	if err := binary.Read(reader, binary.LittleEndian, &tlsFirstCallback); err != nil {
		return pefile.Section{}, fmt.Errorf("Error: tlsFirstCallback %w", err)
	}

	var oep uint32
	if err := binary.Read(reader, binary.LittleEndian, &oep); err != nil {
		return pefile.Section{}, fmt.Errorf("Error: oep %w", err)
	}
	encBlocksCount, _ := reader.ReadByte()
	encBlocks := make([]pefile.EncBlock, encBlocksCount)
	for i := 0; i < int(encBlocksCount); i++ {
		encBlocks[i] = pefile.ReadEncBlock(reader)
	}

	reader.Seek(393, io.SeekCurrent)
	unk, _ := reader.ReadByte()
	if unk != 1 {
		return pefile.Section{}, fmt.Errorf("Error: unk != 1")
	}

	var imageBase uint64
	if err := binary.Read(reader, binary.LittleEndian, &imageBase); err != nil {
		return pefile.Section{}, fmt.Errorf("Error: imageBase %w", err)
	}
	var sizeOfImage uint32
	if err := binary.Read(reader, binary.LittleEndian, &sizeOfImage); err != nil {
		return pefile.Section{}, fmt.Errorf("Error: sizeOfImage %w", err)
	}

	importDir := pefile.ReadDataDir(reader)
	relocDir := pefile.ReadDataDir(reader)
	iatDir := pefile.ReadDataDir(reader)

	return pefile.Section{
		ContentID:   contentId,
		OEP:         uint64(oep),
		EncBlocks:   encBlocks,
		ImageBase:   imageBase,
		SizeOfImage: sizeOfImage,
		ImportDir:   importDir,
		RelocDir:    relocDir,
		IATDir:      iatDir,
	}, nil
}
