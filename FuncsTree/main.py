#!/usr/bin/env ptyhon3

import argparse
import os
import re
import copy

class Color:
    """Used to colorify terminal output."""
    colors = {
        "normal"         : "\033[0m",
        "gray"           : "\033[1;38;5;240m",
        "red"            : "\033[31m",
        "green"          : "\033[32m",
        "yellow"         : "\033[33m",
        "blue"           : "\033[34m",
        "pink"           : "\033[35m",
        "cyan"           : "\033[36m",
        "bold"           : "\033[1m",
        "underline"      : "\033[4m",
        "underline_off"  : "\033[24m",
        "highlight"      : "\033[3m",
        "highlight_off"  : "\033[23m",
        "blink"          : "\033[5m",
        "blink_off"      : "\033[25m",
    }

    def colorify(text, attrs):
        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(str(text))
        msg.append(colors["normal"])
        return "".join(msg)




extensions = {".c"}
headers = {".c": ["#include", [['"', '"'], ['<', '>']]], \
           ".h": ["#include", [['"', '"'], ['<', '>']]]
           }
           
black_list = ["if", "for", "while"]

def check_file_exist(file):
    return os.path.exists(file)

def check_extention_support(ext):
    return ext in extensions

    
class Tracer:
    file = []
    header_file = []
    libs_path = []
    files_path = []
    funcs = {}

    def __init__(self, file, libs_path):
        self.file = file
        self.header_file = copy.deepcopy(file)
        self.libs_path = libs_path

    def parse_header(self, filename, ext):
        """ collect all headers in filename and record its filepath """
        header = headers[ext]
        pattern = header[0]
        patt_len = len(pattern)
        delims = header[1]
        
        for lp in self.libs_path:
            file = lp+'/'+filename
            if check_file_exist(file):
                break
        
        if not check_file_exist(file):
            # print(f"{filename} not found")
            return

        check_extention_support(ext)

        with open(file, "r") as f:
            data = f.readlines()
        
        for line in data:
            if line[:patt_len] == pattern:
                for d in delims:          
                    try:
                        start = line.index(d[0], patt_len) + 1
                        end = line.index(d[1], start)
                        h = line[start:end]
                    except:
                        continue

                    if h not in self.header_file:
                        self.header_file.append(h)
                    break

        if file not in self.files_path:
            self.files_path.append(file)

    def parse_funs(self, file):
        """ collect all funcs and its one level subfuncs """
        with open(file, "r") as f:
            data = ''.join(f.readlines()).replace('\n', '')

        func_pattern = re.compile(r"\([^(){}]*\)[ ]*{[^}]*}")
        subfunc_pattern = re.compile(r"\(")
        st = end = 0
        while True:
            r = func_pattern.search(data[end:])
            if not r:
                break

            st, end = end + r.start(), end + r.end()
            
            func_name_st = data.rfind(' ', 0, st) + 1
            func_name = data[func_name_st:st]
            if len(func_name) < 1:
                continue

            if func_name not in self.funcs:
                self.funcs[func_name] = []

            content = data[st+1:end]
            eend = 0
            while True:
                r = subfunc_pattern.search(content[eend:])
                if not r:
                    break

                sst, eend = eend + r.start(), eend + r.end()
                if not content[sst-1].isalnum():
                    continue

                subfunc_name = re.findall(r'[\w\d]+', content[0:sst])[-1]
                if subfunc_name not in black_list and len(subfunc_name)>1:
                    self.funcs[func_name].append(subfunc_name)
    
    def print_func_tree(self, depth):
        #print("")
        for fn in self.funcs:
            print(Color.colorify(f"{fn}", "red"))
            parent_func = fn
            footprint = [(parent_func, 0)]
            d = 1
            while len(footprint):
                parent_func, idx = footprint[-1]
                footprint = footprint[:-1]
                d -= 1
                while d < depth:
                    try:
                        child_func = self.funcs[parent_func][idx]
                        print(" "*(8*(d+1))+child_func)
                        footprint.append((parent_func, idx+1))
                        parent_func = child_func
                        idx = 0
                        d += 1
                    except:
                        break


    def run(self, depth):
        for f in self.header_file:
            _ , ext = os.path.splitext(f)
            self.parse_header(f, ext)
        
        for f in self.header_file:
            try:
                self.parse_funs(f)
            except:
                pass

        self.print_func_tree(depth)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose")
    parser.add_argument("-i", "--include", help="library path", default=".")
    parser.add_argument("-d", "--depth", help="", default="1")
    requiredArgs = parser.add_argument_group('required arguments')
    requiredArgs.add_argument("-f", "--file", help="files prepared to parse", required=True)
    args = parser.parse_args()
     
    with open(args.file) as f:
        arg_files = list(map(lambda x: x[:-1], f.readlines()))
    
    libs_path = ['.'] + args.include.split()
    assert(all(list(map(check_file_exist, libs_path+arg_files))))

    depth = int(args.depth)
    tracer = Tracer(arg_files, libs_path)
    tracer.run(depth)
