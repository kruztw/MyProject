#!/usr/bin/env ptyhon3

import string
import argparse
import re
import os

class JS:
    filename = ""
    output = ""
    indent = ""

    def __init__(self, filename, output, indent):
        self.filename = filename
        self.output = output if len(output) else filename
        self.indent = indent

    def alignment(self, data):
        
        data = data.lstrip(' \t\n')
        state = ""
        target = ""
        str_syms = ["'", '"', '`']

        out = ""
        level = 0
        func_num = 0

        i = 0
        while i < len(data): 
            if target and data[i:].startswith(target):
                out += target
                i += len(target)
                state = ""
                target = ""
                continue

            if state == "string":
                pass
            elif state == "comment":
                pass
            elif data[i] in str_syms:
                state = "string"
                target = data[i]
            elif data[i] == '\n':
                out += '\n'+(level+func_num)*indent
                i += 1
                continue
            elif data[i] == '}' and func_num > 0:
                func_num -= 1
                out = out[:-len(indent)]
            else:
                func_pattern = re.compile(r"^function[ \t\n]+[\w]+[ \t]*\([^)]*\)[ \t\n]*{")
                r = func_pattern.search(data[i:])
                if r:
                    func_num+=1
                    if len(out) and out[-1] != "\n":
                        out += '\n'
                    
                    padding = (level+func_num) * indent
                    out += data[i+r.start():i+r.end()]
                    i += r.end()
                    continue

            out += data[i]
            i += 1
        
        return out.strip()

    def run(self):
        with open(self.filename, 'r') as f:
            data = ''.join(list(map(lambda x: x.lstrip(' \t'), f.readlines())))

        out = self.alignment(data)
        with open(self.output, 'w') as f:
            f.write(out)


           
class HTML:
    filename = ""
    output = ""
    indent = ""

    def __init__(self, filename, output, indent):
        self.filename = filename
        self.output = output if len(output) else filename
        self.indent = indent

    def alignment(self, data):
        def get_tagname(s):
            off = 0
            tag_name = ''
            for x in s:
                if x in (' ', '\t'): off+=1
                else: break

            for x in s.lstrip(' \t'):
                if x.isalpha(): tag_name += x
                else: break

            return tag_name, off
            

        fixed = ["!DOCTYPE", "html", "head", "body"]
        kv = {"!DOCTYPE":[0], "html":[0], "head":[1], "body":[1]}
        str_syms = ["'", '"', '`']
        threshold = 10
        
        state = ""
        target = ""

        out = ""
        level = 2

        i = 0
        while i < len(data): 
            if target and data[i:].startswith(target):
                out += target
                i += len(target)
                state = ""
                target = ""
                continue

            if state == "string":
                pass
            elif state == "comment":
                pass
            elif data[i] == '\n':
                out += level * indent
            else:
                if data[i] in str_syms:
                    state = "string"
                    target = data[i]
                elif data[i] == '<':
                    pattern     = re.compile(r"^<[ \t]*script[ \t]*>")
                    end_pattern = re.compile(r"<[ \t]*/[ \t]*script[ \t]*>")
                    r = pattern.search(data[i:])
                    if r: # <script>
                        st = i + r.end()
                        r = end_pattern.search(data[st:])
                        end = st + r.start()
                        obj = JS("", "", indent)
                        padding = level * indent
                        result = (padding+indent)+obj.alignment(data[st:end]).replace('\n', '\n'+padding+indent).strip()
                        out += f"{padding}<script>\n"+result+f"\n{padding}</script>"
                        i = st+r.end()
                        continue

                    tag_name, off1 = get_tagname(data[i+1:])

                    if tag_name != "":
                        end_tag = False
                        if tag_name not in fixed:
                           if not kv.get(tag_name, []):
                               kv[tag_name] = []
                           kv[tag_name] += [level]
                           level += 1

                        padding = kv[tag_name][-1]*indent
                        out += padding + '<'
                        i += 1+off1
                    elif data[i+1+off1] == '/': # end tag
                        end_tag = True
                        tag_name, off2 = get_tagname(data[i+2+off1:])
                        if tag_name != "":
                            try:
                                padding = indent*kv[tag_name][-1]
                                out += padding + "</"
                                i += 2+off1+off2
                                if tag_name not in fixed:
                                    level = kv[tag_name][-1]
                                    kv[tag_name] = kv[tag_name][:-1]
                            except:
                                 print(f"{tag_name} not match")
                                 exit()

                    if tag_name != "":
                        continue

                elif data[i] == '>':
                    st  = i+1
                    end = st + data[st:].find('<')
                    if ('\n' not in data[st:end]):
                        out += '>\n'
                        i += 1
                        continue
                
            out += data[i]
            i += 1
        return out.strip()

    def run(self):
        with open(self.filename, 'r') as f:
            data = ''.join(list(map(lambda x: x.lstrip(' \t'), f.readlines())))

        out = self.alignment(data)
        with open(self.output, 'w') as f:
            f.write(out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="input file", required=True)
    parser.add_argument("-o", "--output", help="output file", default="")
    parser.add_argument("-s", "--space", help=" -s <num> seperate with <num> space (default 4)", default=4)
    parser.add_argument("-t", "--tab", help=" -t <num> seperate with <num> tab")
    args = parser.parse_args()
     

    input_file = args.input
    output_file = args.output

    if args.tab:
        indent = '\t' * args.tab
    else:
        indent = ' ' * args.space


    _ , language = os.path.splitext(input_file)
    language = language[1:].upper()

    if language == "HTML":
        obj = HTML(input_file, output_file, indent)
    else:
        print(f"Not supported language: {language}")
        exit()

    obj.run()
