package memory

import (
 "syscall"
 "unsafe"
)

func Unprotect(address uintptr, size uintptr) error {
 protection := uint32(syscall.PAGE_EXECUTE_READWRITE)
 currentProcess, err := syscall.GetCurrentProcess()
 if err != nil {
  return err
 }
 err = syscall.VirtualProtectEx(currentProcess, unsafe.Pointer(address), size, protection, nil)
 if err != nil {
  return err
 }
 return nil
}

func Nop(address uintptr, bytes int) error {
 nopBytes := make([]byte, bytes)
 for i := 0; i < bytes; i++ {
  nopBytes[i] = 0x90
 }
 currentProcess, err := syscall.GetCurrentProcess()
 if err != nil {
  return err
 }
 _, err = syscall.WriteProcessMemory(currentProcess, unsafe.Pointer(address), nopBytes, uintptr(bytes))
 if err != nil {
  return err
 }
 return nil
}

func MemWrite(address uintptr, data []byte) error {
 size := uintptr(len(data))
 currentProcess, err := syscall.GetCurrentProcess()
 if err != nil {
  return err
 }
 _, err = syscall.WriteProcessMemory(currentProcess, unsafe.Pointer(address), data, size)
 if err != nil {
  return err
 }
 return nil
}

func MemFill(address uintptr, value byte, size int) error {
 data := make([]byte, size)
 for i := 0; i < size; i++ {
  data[i] = value
 }
 return MemWrite(address, data)
}
