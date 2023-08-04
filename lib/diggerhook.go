package diggerhook

import (
 "fmt"
 "syscall"
 "unsafe"
)

type Hook struct {
 originalFunc  uintptr
 newFunc       uintptr
 originalBytes []byte
}

func NewHook(targetFunc *syscall.Proc, hookFunc func()) (*Hook, error) {
 hook := &Hook{}

 originalFunc := targetFunc.Addr()
 hookFuncAddr := syscall.NewCallback(hookFunc)

 mod := syscall.NewLazyDLL("kernel32.dll")
 proc := mod.NewProc("VirtualProtect")

 currentProcess, err := syscall.GetCurrentProcess()
 if err != nil {
  return nil, err
 }

 var oldProtect uint32
 ret, _, _ := proc.Call(
  uintptr(currentProcess),
  originalFunc,
  syscallPtrSize,
  syscall.PAGE_EXECUTE_READWRITE,
  uintptr(unsafe.Pointer(&oldProtect)),
 )
 if ret == 0 {
  return nil, fmt.Errorf("failed to change memory protection")
 }

 originalBytes := make([]byte, syscallPtrSize)
 _, err = syscall.ReadProcessMemory(currentProcess, originalFunc, originalBytes, syscallPtrSize)
 if err != nil {
  return nil, err
 }

 hook.newFunc = *(*uintptr)(unsafe.Pointer(&hookFuncAddr))

 _, err = syscall.WriteProcessMemory(currentProcess, originalFunc, (*(*[syscallPtrSize]byte)(unsafe.Pointer(&hook.newFunc)))[:], syscallPtrSize)
 if err != nil {
  return nil, err
 }

 ret, _, _ = proc.Call(
  uintptr(currentProcess),
  originalFunc,
  syscallPtrSize,
  uintptr(oldProtect),
  uintptr(unsafe.Pointer(&oldProtect)),
 )
 if ret == 0 {
  return nil, fmt.Errorf("failed to restore memory protection")
 }

 hook.originalFunc = originalFunc
 hook.originalBytes = originalBytes

 return hook, nil
}

func (h *Hook) Disable() error {
 currentProcess, err := syscall.GetCurrentProcess()
 if err != nil {
  return err
 }

 var oldProtect uint32
 ret, _, _ := syscall.VirtualProtect.Call(
  uintptr(currentProcess),
  h.originalFunc,
  syscallPtrSize,
  syscall.PAGE_EXECUTE_READWRITE,
  uintptr(unsafe.Pointer(&oldProtect)),
 )
 if ret == 0 {
  return fmt.Errorf("failed to change memory protection")
 }

 _, err = syscall.WriteProcessMemory(currentProcess, h.originalFunc, h.originalBytes, syscallPtrSize)
 if err != nil {
  return err
 }

 ret, _, _ = syscall.VirtualProtect.Call(
  uintptr(currentProcess),
  h.originalFunc,
  syscallPtrSize,
  uintptr(oldProtect),
  uintptr(unsafe.Pointer(&oldProtect)),
 )
 if ret == 0 {
  return fmt.Errorf("failed to restore memory protection")
 }

 return nil
}
