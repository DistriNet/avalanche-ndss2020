def translatecode(code):
    out = ''
    for char in code:
        if char == '1':
            out += 'Y'
        else:
            out += 'N'
    return out

def translateyear(year):
    out = 'somethingwentworng'
    if year == '2017':
        out = 'A'
    elif year == '2018':
        out = 'B'
    elif year == '2019':
        out = 'C'
    return out