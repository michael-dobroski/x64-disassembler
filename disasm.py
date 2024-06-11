#!/usr/bin/env python3
import argparse

# key is the opcode
# value is a list of useful information
# 0xOPCODE : dictionary containing every opcode's corresponding info minus the ranged, /digit, and double opcodes
GLOBAL_OPCODE_MAP = {
    0x05 : {'name' : 'add eax, {}', 
            'isModrmRequired' : False, 
            'opEn' : 'i',
            'imm' : 'id'},
    0x01 : {'name' : 'add {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'mr',
            'imm' : None},
    0x03 : {'name' : 'add {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'rm',
            'imm' : None},
    0x25 : {'name' : 'and eax, {}', 
            'isModrmRequired' : False, 
            'opEn' : 'i',
            'imm' : 'id'},
    0x21 : {'name' : 'and {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'mr',
            'imm' : None},
    0x23 : {'name' : 'and {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'rm',
            'imm' : None},
    0xE8 : {'name' : 'call {}', 
            'isModrmRequired' : False, 
            'opEn' : 'd',
            'imm' : 'id'},
    0x3D : {'name' : 'cmp eax, {}', 
            'isModrmRequired' : False, 
            'opEn' : 'i',
            'imm' : 'id'},
    0x39 : {'name' : 'cmp {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'mr',
            'imm' : None},
    0x3B : {'name' : 'cmp {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'rm',
            'imm' : None},
    0xEB : {'name' : 'jmp {}', 
            'isModrmRequired' : False, 
            'opEn' : 'd',
            'imm' : 'ib'},
    0xE9 : {'name' : 'jmp {}', 
            'isModrmRequired' : False, 
            'opEn' : 'd',
            'imm' : 'id'},
    0x74 : {'name' : 'jz {}', 
            'isModrmRequired' : False, 
            'opEn' : 'd',
            'imm' : 'ib'},
    0x75 : {'name' : 'jnz {}', 
            'isModrmRequired' : False, 
            'opEn' : 'd',
            'imm' : 'ib'},
    0x8D : {'name' : 'lea {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'rm',
            'imm' : None},
    0xA1 : {'name' : 'mov eax, {}', 
            'isModrmRequired' : False, 
            'opEn' : 'i',
            'imm' : 'id'},
    0xA3 : {'name' : 'mov {}, eax',
            'isModrmRequired' : False, 
            'opEn' : 'i',
            'imm' : 'id'},
    0xC7 : {'name' : 'mov {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'mi',
            'slash' : '0',
            'imm' : 'id'},
    0x89 : {'name' : 'mov {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'mr',
            'imm' : None},
    0x8B : {'name' : 'mov {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'rm',
            'imm' : None},
    0xA5 : {'name' : 'movsd', 
            'isModrmRequired' : False, 
            'opEn' : 'zo',
            'imm' : None},
    0x90 : {'name' : 'nop', 
            'isModrmRequired' : False, 
            'opEn' : 'zo',
            'imm' : None},
    0x0D : {'name' : 'or eax, {}', 
            'isModrmRequired' : False, 
            'opEn' : 'i',
            'imm' : 'id'},
    0x09 : {'name' : 'or {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'mr',
            'slash' : '/r',
            'imm' : None},
    0x0B : {'name' : 'or {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'rm',
            'slash' : '/r',
            'imm' : None},
    0x8F : {'name' : 'pop {}', 
            'isModrmRequired' : True, 
            'opEn' : 'm',
            'slash' : '/0',
            'imm' : None},
    0x68 : {'name' : 'push {}', 
            'isModrmRequired' : False, 
            'opEn' : 'i',
            'imm' : 'id'},
    0x6A : {'name' : 'push {}', 
            'isModrmRequired' : False, 
            'opEn' : 'i',
            'imm' : 'ib'},
    0xCB : {'name' : 'retf', 
            'isModrmRequired' : False, 
            'opEn' : 'zo',
            'imm' : None},
    0xCA : {'name' : 'retf {}', 
            'isModrmRequired' : False, 
            'opEn' : 'i',
            'imm' : 'iw'},
    0xC3 : {'name' : 'retn', 
            'isModrmRequired' : False, 
            'opEn' : 'zo',
            'imm' : None},
    0xC2 : {'name' : 'retn {}', 
            'isModrmRequired' : False, 
            'opEn' : 'i',
            'imm' : 'iw'},
    0x2D : {'name' : 'sub eax, {}', 
            'isModrmRequired' : False, 
            'opEn' : 'i',
            'imm' : 'id'},
    0x29 : {'name' : 'sub {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'mr',
            'imm' : None},
    0x2B : {'name' : 'sub {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'rm',
            'imm' : None},
    0xA9 : {'name' : 'test eax, {}', 
            'isModrmRequired' : False, 
            'opEn' : 'i',
            'imm' : 'id'},
    0x85 : {'name' : 'test {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'mr',
            'imm' : None},
    0x35 : {'name' : 'xor eax, {}', 
            'isModrmRequired' : False, 
            'opEn' : 'i',
            'imm' : 'id'},
    0x31 : {'name' : 'xor {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'mr',
            'imm' : None},
    0x33 : {'name' : 'xor {}, {}', 
            'isModrmRequired' : True, 
            'opEn' : 'rm',
            'imm' : None},
}

# opcodes that depend on additional information in the ModRM byte to be identified
DIGIT_OPCODE_MAP = {
    0x81 : {0 : {'name' : 'add {}, {}', 
                'isModrmRequired' : True, 
                'opEn' : 'mi',
                'slash' : '0',
                'imm' : 'id'},
            4 : {'name' : 'and {}, {}', 
                'isModrmRequired' : True, 
                'opEn' : 'mi',
                'slash' : '4',
                'imm' : 'id'},
            7 : {'name' : 'cmp {}, {}', 
                'isModrmRequired' : True, 
                'opEn' : 'mi',
                'slash' : '7',
                'imm' : 'id'},
            1 : {'name' : 'or {}, {}', 
                'isModrmRequired' : True, 
                'opEn' : 'mi',
                'slash' : '1',
                'imm' : 'id'},
            5 : {'name' : 'sub {}, {}', 
                'isModrmRequired' : True, 
                'opEn' : 'mi',
                'slash' : '5',
                'imm' : 'id'},
            6 : {'name' : 'xor {}, {}', 
                'isModrmRequired' : True, 
                'opEn' : 'mi',
                'slash' : '6',
                'imm' : 'id'}},
    0xFF : {2 : {'name' : 'call {}', 
                'isModrmRequired' : True, 
                'opEn' : 'm',
                'slash' : '2',
                'imm' : None},
            1 : {'name' : 'dec {}', 
                'isModrmRequired' : True, 
                'opEn' : 'm',
                'slash' : '1',
                'imm' : None},
            0 : {'name' : 'inc {}', 
                'isModrmRequired' : True, 
                'opEn' : 'm',
                'slash' : '0',
                'imm' : None},
            4 : {'name' : 'jmp {}', 
                'isModrmRequired' : True, 
                'opEn' : 'm',
                'slash' : '4',
                'imm' : None},
            6 : {'name' : 'push {}', 
                'isModrmRequired' : True, 
                'opEn' : 'm',
                'slash' : '6',
                'imm' : None}},
    0xF7 : {7 : {'name' : 'idiv {}', 
                'isModrmRequired' : True, 
                'opEn' : 'm',
                'slash' : '7',
                'imm' : None},
            2 : {'name' : 'not {}', 
                'isModrmRequired' : True, 
                'opEn' : 'm',
                'slash' : '2',
                'imm' : None},
            0 : {'name' : 'test {}, {}', 
                'isModrmRequired' : True, 
                'opEn' : 'mi',
                'slash' : '0',
                'imm' : 'id'}}
}

# these opcodes always start at a multiple of 8. they go up to +8 representing each register
# min = "0x" + "%02x" % (opcode // 8 * 8)
# reg = GLOBAL_REGISTER_NAMES[opcode % 8]
# insInfo = RANGE_OPCODES[min]
# these will never require a ModRM byte
RANGED_OPCODES = {
    0x48 : {'name' : 'dec {}', 
            'isModrmRequired' : False, 
            'opEn' : 'o',
            'imm' : None},
    0x40 : {'name' : 'inc {}', 
            'isModrmRequired' : False, 
            'opEn' : 'o',
            'imm' : None},
    0xB8 : {'name' : 'mov {}, {}', 
            'isModrmRequired' : False, 
            'opEn' : 'oi',
            'imm' : 'id'},
    0x58 : {'name' : 'pop {}', 
            'isModrmRequired' : False, 
            'opEn' : 'o',
            'imm' : None},
    0x50 : {'name' : 'push {}', 
            'isModrmRequired' : False, 
            'opEn' : 'o',
            'imm' : None}
}

# these opcodes are actually two bytes long so we gotta make sure we check for this and properly consume them before processing operands
DOUBLE_OPCODES = {
    0x0F : {
        0xAE : {'name' : 'clflush {}',
                'isModrmRequired' : True, 
                'opEn' : 'm',
                'slash' : '7',
                'imm' : None},
        0x84 : {'name' : 'jz {}', 
                'isModrmRequired' : False, 
                'opEn' : 'd',
                'imm' : 'id'},
        0x85 : {'name' : 'jnz {}', 
                'isModrmRequired' : False, 
                'opEn' : 'd',
                'imm' : 'id'}},
    0xF2 : {
        0xA7 : {'name' : 'repne cmpsd', 
                'isModrmRequired' : False, 
                'opEn' : 'zo',
                'imm' : None}}
}

GLOBAL_REGISTER_NAMES = [ 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi' ]

# searches the opcode dictionaries for the corresponding info, returns 'None' if unsuccesful
def getIns(opcode, nextByte):
    if opcode in GLOBAL_OPCODE_MAP.keys():
        return GLOBAL_OPCODE_MAP[opcode]

    if opcode in DIGIT_OPCODE_MAP.keys():
        if nextByte != None:
            _, dig, _ = parseMODRM(nextByte)
            if dig in DIGIT_OPCODE_MAP[opcode].keys():
                return DIGIT_OPCODE_MAP[opcode][dig]
            else:
                return None
        else:
            return None
        
    opcodeFloor8 = opcode // 8 * 8
    if opcodeFloor8 in RANGED_OPCODES.keys():
        ins = RANGED_OPCODES[opcodeFloor8]
        ins['reg'] = GLOBAL_REGISTER_NAMES[opcode % 8]
        return ins
    
    if opcode in DOUBLE_OPCODES:
        if nextByte != None:
            if nextByte in DOUBLE_OPCODES[opcode]:
                return DOUBLE_OPCODES[opcode][nextByte]
            else:
                return None
        else:
            return None

    return None

def parseMODRM(modrm):
    mod = (modrm & 0b11000000) >> 6
    reg = (modrm & 0b00111000) >> 3
    rm  = (modrm & 0b00000111)
    return (mod,reg,rm)

def parseSIB(sib):
    scale = (sib & 0b11000000) >> 6
    index = (sib & 0b00111000) >> 3
    base  = (sib & 0b00000111)
    return (scale, index, base)

def signExtend32(val: int):
    if len(bin(val)) == 10:
        return int('0b' + '1' * 24 + str(bin(val))[2:], 2)
    else:
        return val

branchLabels = {}
def printDisasm( l ):
    for addr in sorted(l):
        if addr in branchLabels:
            print('{}:'.format(branchLabels[addr]))
        print('{}: {: <24}{}'.format(addr, "".join(["%02X" % x for x in l[addr][0]]), l[addr][1]))

def disassemble(b):

    outputList = {}
    i = 0

    while i < len(b):

        opcode = b[i]
        nextByte = b[i + 1] if i + 1 < len(b) else None
        insBytes = bytearray([b[i]])
        insEnglish = ''
        origIndex = i
        counter = "%08X" % origIndex
        outputList[counter] = ['', '']
        op1, op2 = None, None
        i += 1

        ins = getIns(opcode, nextByte)

        if ins:

            try:
                insEnglish = ins['name']

                if ins['isModrmRequired']:
                    modrm = b[i]
                    insBytes.append(b[i])
                    mod, reg, rm = parseMODRM(modrm)
                    i += 1 # MODRM byte is consumed
                    
                    if insEnglish == 'clflush {}': # edge case: clflush contains two opcodes followed by a ModRM byte
                        modrm = b[i]
                        mod, reg, rm = parseMODRM(modrm)
                        if mod == 3:
                            raise IndexError("Illegal Instruction")
                        insBytes.append(b[i])
                        i += 1
                    
                    rmReg = GLOBAL_REGISTER_NAMES[rm]
                    if mod != 3 and rm == 4: # indicates that SIB byte is required
                        sib = b[i]
                        scale, index, base = parseSIB(sib)
                        insBytes.append(b[i])
                        i += 1
                        rmReg = ('' if index == 4 else (GLOBAL_REGISTER_NAMES[index] + '*' + str(2 ** scale))) + ('' if base == 5 and mod == 0 else (('' if index == 4 else ' + ') + GLOBAL_REGISTER_NAMES[base]))
                        if mod == 0 and base == 5:
                            rmReg += " + 0x" + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i]
                            insBytes.extend(b[i : i + 4])
                            i += 4

                    if mod == 3: # direct register access
                        if ins['opEn'] == 'mr':
                            op1 = GLOBAL_REGISTER_NAMES[rm]
                            op2 = GLOBAL_REGISTER_NAMES[reg]
                        if ins['opEn'] == 'rm':
                            op1 = GLOBAL_REGISTER_NAMES[reg]
                            op2 = GLOBAL_REGISTER_NAMES[rm]
                        if ins['opEn'] == 'mi':
                            op1 = GLOBAL_REGISTER_NAMES[rm]
                            op2 = "0x" + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i]
                            insBytes.extend(b[i : i + 4])
                            i += 4
                        if ins['opEn'] == 'm':
                            op1 = GLOBAL_REGISTER_NAMES[rm]
                        if insEnglish == 'lea {}, {}':
                            raise IndexError("Illegal Instruction")

                    if mod == 2: # r/m32 operand is [ reg + disp32 ]
                        if ins['opEn'] == 'mr':
                            op1 = '[ ' + rmReg + " + 0x" + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i] + ' ]'
                            op2 = GLOBAL_REGISTER_NAMES[reg]
                            insBytes.extend(b[i : i + 4])
                            i += 4
                        if ins['opEn'] == 'rm':
                            op1 = GLOBAL_REGISTER_NAMES[reg]
                            op2 = '[ ' + rmReg + " + 0x" + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i] + ' ]'
                            insBytes.extend(b[i : i + 4])
                            i += 4
                        if ins['opEn'] == 'mi':
                            op1 = '[ ' + rmReg + " + 0x" + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i] + ' ]'
                            op2 = "0x" + "%02x" % b[i + 7] + "%02x" % b[i + 6] + "%02x" % b[i + 5] + "%02x" % b[i + 4]
                            insBytes.extend(b[i : i + 8])
                            i += 8
                        if ins['opEn'] == 'm':
                            op1 = '[ ' + rmReg + " + 0x" + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i] + ' ]'
                            insBytes.extend(b[i : i + 4])
                            i += 4

                    if mod == 1: # r/m32 operand is [ reg + disp8 ]
                        disp8 = hex(signExtend32(int("%02x" % b[i], 16))) # disp8 are signed values -> sign extend it if necessary
                        if len(disp8) == 3: # pretty lousy fix but it works. it's here to prevent single dig hex values from printing as "0x6" or "0xc" instead of the intended "0x06" and "0x0c"
                            disp8 = '0x0' + disp8[-1]
                        if ins['opEn'] == 'mr':
                            op1 = '[ ' + rmReg + " + " + disp8 + ' ]'
                            op2 = GLOBAL_REGISTER_NAMES[reg]
                            insBytes.extend(b[i : i + 1])
                            i += 1
                        if ins['opEn'] == 'rm':
                            op1 = GLOBAL_REGISTER_NAMES[reg]
                            op2 = '[ ' + rmReg + " + " + disp8 + ' ]'
                            insBytes.extend(b[i : i + 1])
                            i += 1
                        if ins['opEn'] == 'mi':
                            op1 = '[ ' + rmReg + " + " + disp8 + ' ]'
                            op2 = "0x" + "%02x" % b[i + 4] + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1]
                            insBytes.extend(b[i : i + 5])
                            i += 5
                        if ins['opEn'] == 'm':
                            op1 = '[ ' + rmReg + " + " + disp8 + ' ]'
                            insBytes.extend(b[i : i + 1])
                            i += 1

                    if mod == 0:
                        if rm == 5: # r/m32 operand is [ disp32 ]
                            if ins['opEn'] == 'mr':
                                op1 = '[ ' + "0x" + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i] + ' ]'
                                op2 = GLOBAL_REGISTER_NAMES[reg]
                                insBytes.extend(b[i : i + 4])
                                i += 4
                            if ins['opEn'] == 'rm':
                                op1 = GLOBAL_REGISTER_NAMES[reg]
                                op2 = '[ ' + "0x" + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i] + ' ]'
                                insBytes.extend(b[i : i + 4])
                                i += 4
                            if ins['opEn'] == 'mi':
                                op1 = '[ ' + "0x" + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i] + ' ]'
                                op2 = "0x" + "%02x" % b[i + 7] + "%02x" % b[i + 6] + "%02x" % b[i + 5] + "%02x" % b[i + 4]
                                insBytes.extend(b[i : i + 8])
                                i += 8
                            if ins['opEn'] == 'm':
                                op1 = '[ ' + "0x" + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i] + ' ]'
                                insBytes.extend(b[i : i + 4])
                                i += 4

                        else: # r/m32 operand is [ reg ]
                            if ins['opEn'] == 'mr':
                                op1 = '[ ' + rmReg + ' ]'
                                op2 = GLOBAL_REGISTER_NAMES[reg]
                            if ins['opEn'] == 'rm':
                                op1 = GLOBAL_REGISTER_NAMES[reg]
                                op2 = '[ ' + rmReg + ' ]'
                            if ins['opEn'] == 'mi':
                                op1 = '[ ' + rmReg + ' ]'
                                op2 = "0x" + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i]
                                insBytes.extend(b[i : i + 4])
                                i += 4
                            if ins['opEn'] == 'm':
                                op1 = '[ ' + rmReg + ' ]'

                if not ins['isModrmRequired']:
                    if ins['opEn'] == 'i':
                        if ins['imm'] == 'ib':
                            insBytes.extend(b[i : i + 1])
                            op1 = hex(signExtend32(int("%02x" % b[i], 16)))
                            if len(op1) == 3:
                                op1 = '0x0' + op1[-1]
                            i += 1
                        if ins['imm'] == 'iw':
                            insBytes.extend(b[i : i + 2])
                            op1 = "0x" + "%02x" % b[i + 1] + "%02x" % b[i]
                            i += 2
                        if ins['imm'] == 'id':
                            insBytes.extend(b[i : i + 4])
                            op1 = "0x" + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i]
                            i += 4
                    if ins['opEn'] == 'o':
                        op1 = ins['reg']
                    if ins['opEn'] == 'oi':
                        op1 = ins['reg']
                        op2 = "0x" + "%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i]
                        insBytes.extend(b[i : i + 4])
                        i += 4
                    if ins['opEn'] == 'd':
                        if opcode == 0x0F: # jz and jnz with first opcode byte 0x0F consume two bytes for the full opcode
                            insBytes.extend(b[i : i + 1])
                            i += 1
                        if ins['imm'] == 'ib':
                            displacement = signExtend32(int("%02x" % b[i], 16))
                            branchTarget = origIndex + 2 + displacement
                            insBytes.extend(b[i : i + 1])
                            i += 1
                        if ins['imm'] == 'id':
                            displacement = int("%02x" % b[i + 3] + "%02x" % b[i + 2] + "%02x" % b[i + 1] + "%02x" % b[i], 16)
                            branchTarget = origIndex + 5 + displacement
                            insBytes.extend(b[i : i + 4])
                            i += 4
                        if branchTarget > 0xFFFFFFFF:
                            branchTarget = int(str(hex(branchTarget))[3:], 16)
                        op1 = 'offset_' + "%08X" % branchTarget + 'h'
                        branchLabels[str("%08X" % branchTarget)] = op1
                    if opcode == 0xF2: # repne cmpsd consumes two bytes for opcode. no operands, so just make sure it consumes the next bit
                        insBytes.extend(b[i : i + 1])
                        i += 1
                        
                insEnglish = ins['name'].format(op1, op2)

            except IndexError:
                i = origIndex + 1
                outputList[counter][0] = insBytes[:1]
                outputList[counter][1] = 'db 0x%02x' % (int(opcode) & 0xff)
                continue

        if not ins:
            insEnglish = 'db 0x%02x' % (int(opcode) & 0xff)

        outputList[counter][0] = insBytes
        outputList[counter][1] = insEnglish

    printDisasm(outputList)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--filename', help='Specify binary file to disassemble', dest='filename', required=False)
    args = parser.parse_args()
    binary = []

    if args.filename:
        try:
            binFile = open(args.filename, mode="rb")
            binary = binFile.read()
        except IOError:
            print("Error: File not found.")
            
    else:
        print("Error: Please specify a filename using the 'py disasm.py -i [filename]' format.")

    disassemble(binary)

if __name__ == '__main__':
    main()
