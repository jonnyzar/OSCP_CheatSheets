# Into

This script is intended for finding stack-based buffer overflows using fuzzing method and injecting shell code in it to achieve RCE.

## Spiking

* This function is used to test input parameters of the target for BoF

`bofer.py spike 127.0.0.1 80`


## Fuzzying

* This step is intended for finding BoF vulnerability and its offset
* Usage:
`bofer.py fuzz 127.0.0.1 80 -s 10`

Where `-s 10` is indicator for step length

## Injection

* Shell code can be injecting using this functions:

`bofer.py -x 'TRUN /.:/' -n $offset -c $payload inject 127.0.0.1 80`
