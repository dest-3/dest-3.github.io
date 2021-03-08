---
title: "Exploring Artifacts: Windows In-memory Shellcode Runner w/ Powershell & C#"
date: 2021-08-04
tags: [posts]
excerpt: "123"
---
Introduction
---
<img src="{{ site.url }}{{ site.baseurl }}/images/expezr.jpg" alt="">



```
int MessageBox(
    HWND hWnd, 
    LPCTSTR lpText, 
    LPCTSTR lpCaption, 
    UINT uType
);
```

Complete Powershell POC:

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

Before executing the powershell script, 