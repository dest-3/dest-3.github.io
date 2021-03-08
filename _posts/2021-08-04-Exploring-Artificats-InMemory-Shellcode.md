---
title: "Exploring Artifacts: Windows In-memory Shellcode Runner"
date: 2021-08-04
tags: [posts]
excerpt: "123"
---
Introduction
---
<img src="{{ site.url }}{{ site.baseurl }}/images/expezr.jpg" alt="">

While doing research in windows primary memory shellcode injection by leveraging win32 APIs (CreateThread, VirtualAlloc), I was also interested in how the use of this technique can be identified from a blue-team prerspective. This led me through a rabbit whole of exloring artifacts created when using the Add-Type keyword in powershell to compile C# code contating Win32 API declarations.
In this blogpost, we will explore how to we can take this technique further by avoiding the creation of these artifacts with the goal of evading anti-virus and EDR solutions.

Exploring the Artifacts
---

---
```
int MessageBox(
    HWND hWnd, 
    LPCTSTR lpText, 
    LPCTSTR lpCaption, 
    UINT uType
);
```
---
Complete Powershell POC:
---
```
$User32 = @"
using System;
using System.Runtime.InteropServices;
public class User32 {
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int MessageBox(IntPtr hWnd, String text, 
        String caption, int options);
}
"@

Add-Type $User32
[User32]::MessageBox(0, "This is an alert", "MyBox", 0)
```
---

Before executing the powershell script, 