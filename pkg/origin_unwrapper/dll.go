package origin_unwrapper

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"

	"github.com/ricochhet/origin_unwrapper/pkg/pefile"
)

type DLLEntry struct {
	DLL   string
	Names []string
}

func stringToBytes(input string) []byte {
	tmp := []byte(input)
	tmp = append(tmp, bytes.Repeat([]byte{0}, 2-(len(tmp)%2))...)
	return tmp
}

func patchImportTable(file *pefile.Data, address int, dllsToAdd []DLLEntry, addInFront bool) ([]byte, error) {
	if len(dllsToAdd) == 0 {
		return nil, fmt.Errorf("Error: patchImportTable()\n")
	}

	optionalHeader := file.PE.OptionalHeader.(*pe.OptionalHeader64)

	var importDirectory pe.DataDirectory
	if optionalHeader != nil {
		dataDirectories := optionalHeader.DataDirectory
		if len(dataDirectories) > int(pe.IMAGE_DIRECTORY_ENTRY_IMPORT) {
			importDirectory = dataDirectories[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		}
	}

	importDirectoryDDOffset, err := pefile.ReadDDEntryOffset(file.Bytes, importDirectory.VirtualAddress, importDirectory.Size)
	if importDirectoryDDOffset == -1 || err != nil {
		return nil, err
	}

	importDirectoryBytes, err := pefile.ReadSectionBytes(file, importDirectory.VirtualAddress, importDirectory.Size)
	if err != nil {
		return nil, err
	}

	var addresses [][]int
	var result []byte

	for _, entry := range dllsToAdd {
		addresses = append(addresses, []int{address})
		nameBytes := stringToBytes(entry.DLL)
		result = append(result, nameBytes...)
		address += len(nameBytes)
	}

	var allNameAddresses [][]int

	for _, names := range dllsToAdd {
		var nameAddresses []int

		for _, name := range names.Names {
			nameAddresses = append(nameAddresses, address)
			nameBytes := stringToBytes(name)
			result = append(result, 0x00, 0x00)
			result = append(result, nameBytes...)
			address += 2 + len(nameBytes)
		}

		allNameAddresses = append(allNameAddresses, nameAddresses)
	}

	for i, nameAddresses := range allNameAddresses {
		addresses[i] = append(addresses[i], address)
		nameAddresses = append(nameAddresses, 0)

		var tmpBuffer bytes.Buffer
		for _, nameAddress := range nameAddresses {
			err := binary.Write(&tmpBuffer, binary.LittleEndian, int64(nameAddress))
			if err != nil {
				panic(err)
			}
		}

		tmp := tmpBuffer.Bytes()
		result = append(result, tmp...)
		address += len(tmp)
	}

	if optionalHeader != nil {
		dataDirectories := optionalHeader.DataDirectory
		if len(dataDirectories) > int(pe.IMAGE_DIRECTORY_ENTRY_IMPORT) {
			importDirectory.VirtualAddress = uint32(address)
		}
	}

	var newImportDirectoryDDEntry []byte
	newImportDirectoryVirtualAddress := make([]byte, 4)
	binary.LittleEndian.PutUint32(newImportDirectoryVirtualAddress, uint32(address))
	newImportDirectoryDDEntry = append(newImportDirectoryDDEntry, newImportDirectoryVirtualAddress...)

	var addedData []byte
	for _, a := range addresses {
		bytes := make([]byte, 20)
		binary.LittleEndian.PutUint32(bytes[12:], uint32(a[0]))
		binary.LittleEndian.PutUint32(bytes[16:], uint32(a[1]))
		addedData = append(addedData, bytes...)
	}

	var newImportDirectoryBytes []byte
	if addInFront {
		newImportDirectoryBytes = append(addedData, importDirectoryBytes...)
	} else {
		importDirectoryBytesLength := len(importDirectoryBytes)
		newImportDirectoryBytes = append(importDirectoryBytes[:importDirectoryBytesLength-20], addedData...)
		newImportDirectoryBytes = append(newImportDirectoryBytes, importDirectoryBytes[importDirectoryBytesLength-20:]...)
	}

	if optionalHeader != nil {
		dataDirectories := optionalHeader.DataDirectory
		if len(dataDirectories) > int(pe.IMAGE_DIRECTORY_ENTRY_IMPORT) {
			if addInFront {
				newImportDirectorySize := make([]byte, 4)
				binary.LittleEndian.PutUint32(newImportDirectorySize, uint32(len(newImportDirectoryBytes)))
				newImportDirectoryDDEntry = append(newImportDirectoryDDEntry, newImportDirectorySize...)
			}
		}
	}

	if len(newImportDirectoryDDEntry) > 8 {
		return nil, fmt.Errorf("Error: newImportDirectoryDDEntry > 8\n")
	}

	result = append(result, newImportDirectoryBytes...)
	pefile.WriteBytes(file.Bytes, importDirectoryDDOffset, newImportDirectoryDDEntry)
	return result, nil
}

func AddDLLImports(file *pefile.Data, section pe.Section, newSectionName string, dllsToAdd []DLLEntry, addInFront bool) error {
	sectionSizeBytes := make([]byte, 2048)
	binary.LittleEndian.PutUint32(sectionSizeBytes, section.Size)
	pefile.WriteBytes(file.Bytes, int(section.Offset), sectionSizeBytes)

	imports, err := patchImportTable(file, int(section.VirtualAddress), dllsToAdd, addInFront)
	if err != nil {
		return err
	}

	pefile.WriteBytes(file.Bytes, int(section.Offset), imports)
	shSize, err := pefile.ReadSHSize(file.PE)
	if err != nil {
		return err
	}

	shBytes, err := pefile.ReadSHBytes(file.Bytes, shSize)
	if err != nil {
		return err
	}

	shtFind, err := pefile.FindBytes(shBytes, pefile.PadBytes([]byte(section.Name), 8))
	if err != nil {
		return err
	}

	if shtFind != -1 {
		offset, err := pefile.ReadSHEntryOffset(file.Bytes, shtFind)
		if err != nil {
			return err
		}

		if err := pefile.WriteBytes(file.Bytes, offset, pefile.PadBytes([]byte(newSectionName), 8)); err != nil {
			return err
		}

		if err := pefile.WriteBytes(file.Bytes, offset+pefile.SH32_NAME_SIZE+pefile.SH32_SIZE, []byte{0x40, 0x00, 0x00, 0xC0}); err != nil {
			return err
		}
	}

	return nil
}
