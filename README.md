# Installation

```
go install github.com/wr3nch0x1/goasseter@latest

```

# Sample Commands

## For Active Assets

```
goasseter active --input httpx_out.json --output active.csv
```

## For Inactive Assets

```
goasseter active --input resolved.txt --output active.csv
```


## For Screenshots Assets

```
goasseter screenshot --input httpx.json --output screenshot.json
```


## To run everything at once

```
goasseter onego --input resolved.txt
```
