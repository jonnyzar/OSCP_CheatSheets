# Random Tricks

## SSH

* ignore host key

```bash

ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" user@host
```