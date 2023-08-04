package main

import (
 "fmt"
 "memory"
 "syscall"
 "unsafe"
)

func main() {
 address := uintptr(0x1234)

 err := memory.Unprotect(address, 4)
 if err != nil {
  fmt.Println("Ошибка при снятии защиты с памяти:", err)
  return
 }

 err = memory.Nop(address, 4)
 if err != nil {
  fmt.Println("Ошибка при записи NOP-опкодов в память:", err)
  return
 }

 data := []byte{0x11, 0x22, 0x33, 0x44}
 err = memory.MemWrite(address, data)
 if err != nil {
  fmt.Println("Ошибка при записи данных в память:", err)
  return
 }

 err = memory.MemFill(address, 0x00, 4)
 if err != nil {
  fmt.Println("Ошибка при заполнении памяти:", err)
  return
 }

 currentProcess, err := syscall.GetCurrentProcess()
 if err != nil {
  fmt.Println("Ошибка при получении хендла текущего процесса:", err)
  return
 }

 var readData [4]byte
 n, err := syscall.ReadProcessMemory(currentProcess, unsafe.Pointer(address), readData[:], 4)
 if err != nil {
  fmt.Println("Ошибка при чтении данных из памяти:", err)
  return
 }

 fmt.Printf("Прочитано %d байт из памяти: %vn", n, readData)
}
