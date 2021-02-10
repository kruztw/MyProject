## FuncFlow

FuncFlow 的功能是將程式碼使用到的 functions 以類似 pstree 的形似印出

## Usage

```
usage: main.py [-h] [-v VERBOSE] [-i INCLUDE] -f FILE

optional arguments:
  -h, --help            show this help message and exit
  -v VERBOSE, --verbose VERBOSE
  -i INCLUDE, --include INCLUDE
                        library path

required arguments:
  -f FILE, --file FILE  files prepared to parse
```


## Example

![example](/FuncsFlow/example.png)

## TODO

1. pstree 格式化輸出
2. 可選擇深度 (目前: depth=1)
3. 支援多種語言 (目前僅支援 C) 
