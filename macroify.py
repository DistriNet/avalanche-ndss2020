def macroify(dct):
    result_string = ""
    for k, v in dct.items():
        result_string += "{}\n".format(macroify_single(k, v))
    return result_string

def macroify_single(key, value):
    return "\\newcommand{{\\{key}}}{{{value}}}".format(key=key, value=value)

def append_file(dct):
    with open('latexvariables.txt','a') as myfile:
        myfile.write(macroify(dct))

def new_file(dct):
    with open('latexvariables.txt', 'w+') as myfile:
        myfile.write(macroify(dct))

if __name__ == '__main__':
    print(macroify({"a": 123, "b": 456, "c": "ABC"}))