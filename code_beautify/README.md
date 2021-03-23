# code_beautify

HTML 有 tidy, 

javascript 有 js-beautify,

但找不到可以同時處理兩者的指令, 

所以自己寫一個, 方便自行修改.


## Usage

```
usage: main.py [-h] -i INPUT [-o OUTPUT] [-s SPACE] [-t TAB]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        input file
  -o OUTPUT, --output OUTPUT
                        output file
  -s SPACE, --space SPACE
                        -s <num> seperate with <num> space (default 4)
  -t TAB, --tab TAB     -t <num> seperate with <num> tab
```


## Example

![example](/code_beautify/example.png)

## TODO

1. 支援更多語言
2. 優化 code
