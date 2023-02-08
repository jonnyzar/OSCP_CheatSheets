# Random Tricks

## SSH

* ignore host key

```bash

ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" user@host
```

## Dirbusting

* extract only reachable directories

`grep -v 403 dirs_dump.log | grep '//' | uniq -i | cut -d ' ' -f 1 > dirs.txt`