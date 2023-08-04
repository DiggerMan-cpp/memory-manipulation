package main

import (
 "fmt"
 "syscall"
 "libs/diggerhook"
)

func main() {
 originalFunc, err := syscall.LoadDLL("target.dll").FindProc("originalFunc")
 if err != nil {
  fmt.Println("Ошибка при загрузке функции:", err)
  return
 }

 hookedFunc := func() {
  fmt.Println("Перехваченная функция")
 }

 hook, err := diggerhook.NewHook(originalFunc, hookedFunc)
 if err != nil {
  fmt.Println("Ошибка при перехвате функции:", err)
  return
 }

 defer hook.Disable()

 fmt.Println("Вызов оригинальной функции:")
 originalFunc.Call()

 fmt.Println("Вызов перехваченной функции:")
 hookedFunc()
}
