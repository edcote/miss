#!/usr/bin/env python

# Experiment to modify SimpleMIPS to load elftools library
# Original code : http://code.google.com/p/mipsim-python/downloads/detail?name=SimpleMIPS-0.1.py

import os
import sys
import logging

from elftools.elf.elffile import ELFFile

class Memory(object):
    def __init__(self, args):
        self.args = args
        self.memory = bytearray(512 * 2 ** 20)
        self.logger = logging.getLogger('MEMORY')

    def va2pa(self, va):
        if va >= 0xC0000000 and va <= 0xFFFFFFFF:  # kseg2 (1 GB)
            self.logger.error('kseg2 not supported')
        elif va >= 0xA0000000 and va <= 0xBFFFFFFF:  # kseq1 (512 MB)
            pa = va & 0x1FFFFFFF  # strip off leading 3 bits
        elif va >= 0x80000000 and va <= 0x9FFFFFFF:  # kseq0 (512 MB)
            self.logger.error('kseg0 not supported')
        else:  # kuseg (2 GB)
            self.logger.error('kuseg not supported')
        return pa

    def read(self, va):
        pa = self.va2pa(va)
        self.logger.debug('READ: va=0x{:x} pa=0x{:x}'.format(va, pa))
        data = (self.memory[pa + 3] << 24) + (self.memory[pa + 2] << 16) + (self.memory[pa + 1] << 8) + self.memory[pa]
        self.logger.info('READ_DATA: va=0x{:x} pa=0x{:x} data=0x{:x}'.format(va, pa, data))
        return data

    def write(self, va, data):
        pa = self.va2pa(va)
        self.memory[pa + 3] = (data and 0xFF000000) >> 24
        self.memory[pa + 2] = (data and 0x00FF0000) >> 16
        self.memory[pa + 1] = (data and 0x0000FF00) >> 8
        self.memory[pa + 0] = (data and 0x000000FF)
        self.logger.debug('WRITE: va=0x{:x} pa=0x{:x} data=0x{:x}'.format(va, pa, data))

    def load(self, section):
        name = section.name
        va = section.header.sh_addr
        pa = self.va2pa(va)
        length = section.header.sh_size
        self.logger.debug('LOAD:{} va=0x{:x} pa=0x{:x} length=0x{:x}'.format(name, va, pa, length))
        tmp = section.data()
        self.memory[pa:pa + length] = tmp


class Cpu(object):
    def __init__(self, args):
        self.args = args
        self.rf = [0] * 32
        self.rf[28] = 0x10008000  # $gp
        self.rf[29] = 0x80000000  # $sp
        self.cop0_rf = [0] * 32
        self.cop1_rf = [0] * 32
        self.cop2_rf = [0] * 32
        self.cop3_rf = [0] * 32
        self.pc = 0xBFC00000
        self.hi = 0
        self.lo = 0
        self.logger = logging.getLogger('CPU')

    def __str__(self):
        return 'pc=0x{:x}'.format(self.pc)


class Instruction(object):
    def __init__(self, ir):
        self.ir = ir
        self.opcode = ir >> 26
        self.rs = (ir >> 21) & 31
        self.rt = (ir >> 16) & 31
        self.rd = (ir >> 11) & 31
        self.amt = (ir >> 6) & 31
        self.imm = ir & 0xffff
        self.optype = ir & 63
        self.target = ir & 0x3ffffff
        self.logger = logging.getLogger('INSTRUCTION')

    def __str__(self):
        return 'ir=0x{:x} opcode=0x{:x}'.format(self.ir, self.opcode)


class Miss(object):
    def __init__(self, args):
        self.args = args
        self.memory = Memory(args)
        self.cpu = Cpu(args)
        self.elf_file = ()
        self.logger = logging.getLogger('MISS')
        self.opcode_map = {0: self.arith,
                           1: self.blt,
                           2: self.j,
                           3: self.jal,
                           4: self.beq,
                           5: self.bne,
                           6: self.ble,
                           7: self.bgt,
                           8: self.addi,
                           9: self.addiu,
                           10: self.slti,
                           11: self.sltiu,
                           12: self.andi,
                           13: self.ori,
                           14: self.xori,
                           15: self.lui,
                           16: self.cop0,
                           17: self.cop1,
                           18: self.cop2,
                           19: self.cop3,
                           20: self.beql,
                           21: self.bnel,
                           32: self.lb,
                           34: self.lwl,
                           35: self.lw,
                           36: self.lbu,
                           37: self.lhu,
                           38: self.lwr,
                           40: self.sb,
                           41: self.sh,
                           42: self.swl,
                           43: self.sw,
                           46: self.swr,
                           47: self.cache}

        self.optype_map = {0: self.sll,
                           2: self.srl,
                           3: self.sra,
                           4: self.sllv,
                           9: self.jalr,
                           8: self.jr,
                           16: self.mfhi,
                           18: self.mflo,
                           24: self.mult,
                           25: self.multu,
                           26: self.div,
                           33: self.addu,
                           35: self.subu,
                           36: self._and,
                           37: self._or,
                           38: self.xor,
                           39: self.nor,
                           42: self.slt,
                           43: self.sltu}

    def load_elf(self):
        f = open(self.args.file, 'rb')
        self.elf_file = ELFFile(f)

        for section in self.elf_file.iter_sections():
            name = section.name
            if name in ['.text', '.bss', '.rodata', '.data']:
                self.memory.load(section)

    def execute(self):
        if not self.elf_file:
            self.load_elf()

        f = open('instr_trace.txt', 'w')

        in_delay_slot = False
        saved_pc = 0

        while True:
            # Fetch / Decode
            instr = Instruction(self.memory.read(self.cpu.pc))

            self.cpu.npc = self.cpu.pc + 4

            if instr.opcode not in self.opcode_map:
                self.logger.error('Illegal opcode {:b}b'.format(instr.opcode))

            # Write to trace file

            opcode_name = self.opcode_map[instr.opcode].__name__
            if opcode_name == 'arith':
                if instr.ir == 0:
                    opcode_name = 'nop'
                else:
                    opcode_name = self.optype_map[instr.optype].__name__


            instr_trace = 'opcode={} pc=0x{:x}'.format(opcode_name, self.cpu.pc)
            f.write(instr_trace + '\n')
            self.logger.info(instr_trace)

            # Execute
            jump = self.opcode_map[instr.opcode](instr)
            self.cpu.rf[0] = 0

            # Handle branch and jump instructions
            if in_delay_slot:
                self.cpu.pc = saved_pc
                in_delay_slot = False
            elif jump:
                saved_pc = self.cpu.pc
                in_delay_slot = True
                self.cpu.pc = self.cpu.npc  # advance to instruction following branch/jump
            else:
                self.cpu.pc = self.cpu.npc

        f.close()

    def to_signed(self, num, bits):
        if num & (1 << (bits - 1)) > 0:
            return num - (1 << bits)
        else:
            return num

    def to_unsigned(self, num):
        if num >= 0:
            return num
        else:
            return 0x100000000 + num

    def arith(self, instr):
        return self.optype_map[instr.optype](instr)

    def addi(self, instr):
        self.cpu.rf[instr.rt] = self.to_unsigned((self.cpu.rf[instr.rs] + self.to_signed(instr.imm, 16)) & 0xffffffff)

    def addiu(self, instr):
        self.cpu.rf[instr.rt] = self.to_unsigned((self.cpu.rf[instr.rs] + self.to_signed(instr.imm, 16)) & 0xffffffff)

    def sw(self, instr):
        self.cpu.mem.Write(self.to_signed(instr.imm,16)+self.cpu.rf[instr.rs],self.cpu.rf[instr.rt],self.cpu.pc)

    def addu(self, instr):
        self.cpu.rf[instr.rd] = self.to_unsigned((self.cpu.rf[instr.rs]+self.cpu.rf[instr.rt]) & 0xffffffff)

    def subu(self, instr):
        self.cpu.rf[instr.rd] = self.to_unsigned((self.cpu.rf[instr.rs]-self.cpu.rf[instr.rt]) & 0xffffffff)

    def _and(self, instr):
         self.cpu.rf[instr.rd] = self.cpu.rf[instr.rs] & self.cpu.rf[instr.rt]

    def _or(self, instr):
         self.cpu.rf[instr.rd] = self.cpu.rf[instr.rs] | self.cpu.rf[instr.rt]

    def nor(self, instr):
         self.cpu.rf[instr.rd] =~(self.cpu.rf[instr.rs] | self.cpu.rf[instr.rt])

    def jr(self, instr):
        self.cpu.pc = self.cpu.rf[instr.rs]
        return 1

    def slt(self, instr):
        if self.to_signed(self.cpu.rf[instr.rs],32)<self.to_signed(self.cpu.rf[instr.rt],32):
            self.cpu.rf[instr.rd] = 1
        else:
            self.cpu.rf[instr.rd] = 0

    def sltu(self, instr):
        if self.cpu.rf[instr.rs]<self.cpu.rf[instr.rt]:
            self.cpu.rf[instr.rd] = 1
        else:
            self.cpu.rf[instr.rd] = 0

    def mult(self, instr):
        result = self.to_signed(self.cpu.rf[instr.rs],32)*self.to_signed(self.cpu.rf[instr.rt],32)
        self.cpu.lo = self.to_unsigned(result & 0xffffffff)
        self.cpu.hi = self.to_unsigned(result>>32)

    def div(self, instr):
        op1 = self.to_signed(self.cpu.rf[instr.rs],32)
        op2 = self.to_signed(self.cpu.rf[instr.rt],32)
        self.cpu.lo = self.to_unsigned(op1/op2)
        self.cpu.hi = self.to_unsigned(op1%op2)

    def multu(self, instr):
        result = self.cpu.rf[instr.rs]*self.cpu.rf[instr.rt]
        self.cpu.lo = self.to_unsigned(result & 0xffffffff)
        self.cpu.hi = self.to_unsigned(result>>32)

    def mflo(self, instr):
        self.cpu.rf[instr.rd] = self.cpu.lo

    def mfhi(self, instr):
        self.cpu.rf[instr.rd] = self.cpu.hi

    def jalr(self, instr):
        self.cpu.rf[31] = self.cpu.pc+8
        self.cpu.pc = self.cpu.rf[instr.rs]
        return 1

    def srl(self, instr):
        self.cpu.rf[instr.rd] = self.cpu.rf[instr.rt] >> instr.amt

    def sra(self, instr):
        highbit = (self.cpu.rf[instr.rt]&0x80000000)>>31
        dup = (highbit<<instr.amt)-highbit
        self.cpu.rf[instr.rd] = (self.cpu.rf[instr.rt] + (dup << 32)) >> instr.amt

    def sll(self, instr):
        if instr.rd == 0 and instr.rt == 0 and instr.rd == 0 and instr.amt == 3:
            pass
        else:
            self.cpu.rf[instr.rd] = (self.cpu.rf[instr.rt] << instr.amt) & 0xffffffff

    def sllv(self, instr):
        self.cpu.rf[instr.rd] = (self.cpu.rf[instr.rt] << self.cpu.rf[instr.rs]) & 0xffffffff

    def xor(self, instr):
        self.cpu.rf[instr.rd] = self.cpu.rf[instr.rt] ^ self.cpu.rf[instr.rs]

    def beq(self, instr):
        if self.cpu.rf[instr.rs] == self.cpu.rf[instr.rt]:
            self.cpu.pc = self.cpu.pc + 4 + self.to_signed(instr.imm, 16) * 4
        return 1

    def bne(self, instr):
        if self.cpu.rf[instr.rs]!=self.cpu.rf[instr.rt]:
            self.cpu.pc = self.cpu.pc + 4 + self.to_signed(instr.imm,16)*4
            return 1

    def lw(self, instr):
        self.cpu.rf[instr.rt] = self.memory.read(self.cpu.rf[instr.rs] + self.to_signed(instr.imm, 16))

    def lb(self, instr):
        # global bigendian
        addr = self.cpu.rf[instr.rs]+self.to_signed(instr.imm,16)
        base = addr&0xfffffffc
        offset = addr&3
        if bigendian:
            offset = 3 - offset
        mask = 0xff<<(offset*8)
        self.cpu.rf[instr.rt] = self.to_signed((self.cpu.mem.Read(base,self.cpu.pc)&mask)>>(8*offset),8)

    def sb(self, instr):
        # global bigendian
        addr = self.cpu.rf[instr.rs]+self.to_signed(instr.imm,16)
        base = addr&0xfffffffc
        offset = addr&3
        if bigendian:
            offset = 3 - offset
        mask = 0xff<<(offset*8)
        self.cpu.mem.Write(base,(self.cpu.mem.Read(base,self.cpu.pc)&(~mask))|((self.cpu.rf[instr.rt]&0xff)<<(offset*8)),self.cpu.pc)

    def sh(self, instr):
        # global bigendian
        addr = self.cpu.rf[instr.rs]+self.to_signed(instr.imm,16)
        base = addr&0xfffffffc
        offset = addr&3
        if bigendian:
            offset = 2 - offset
        mask = 0xffff<<(offset*8)
        self.cpu.mem.Write(base,(self.cpu.mem.Read(base,self.cpu.pc)&(~mask))|((self.cpu.rf[instr.rt]&0xffff)<<(offset*8)),self.cpu.pc)

    def lbu(self, instr):
        # global bigendian
        addr = self.cpu.rf[instr.rs]+self.to_signed(instr.imm,16)
        base = addr&0xfffffffc
        offset = addr&3
        if bigendian:
            offset = 3 - offset
        mask = 0xff<<(offset*8)
        self.cpu.rf[instr.rt] = (self.cpu.mem.Read(base,self.cpu.pc)&mask)>>(8*offset)

    def lhu(self, instr):
        # global bigendian
        #addr = self.cpu.rf[instr.rs]+self.to_signed(instr.imm,16)
        base = addr&0xfffffffc
        offset = addr&3
        if bigendian:
            offset = 2 - offset
        mask = 0xffff<<(offset*8)
        self.cpu.rf[instr.rt] = (self.cpu.mem.Read(base,self.cpu.pc)&mask)>>(8*offset)

    def slti(self, instr):
        if self.to_signed(self.cpu.rf[instr.rs],32)<self.to_signed(instr.imm,16):
            self.cpu.rf[instr.rt] = 1
        else:
            self.cpu.rf[instr.rt] = 0

    def sltiu(self, instr):
        if self.cpu.rf[instr.rs]<instr.imm:
            self.cpu.rf[instr.rt] = 1
        else:
            self.cpu.rf[instr.rt] = 0

    def lui(self, instr):
        self.cpu.rf[instr.rt] = (instr.imm << 16) & 0xffffffff

    def ori(self, instr):
        self.cpu.rf[instr.rt] = self.cpu.rf[instr.rs] | instr.imm

    def andi(self, instr):
        self.cpu.rf[instr.rt] = self.cpu.rf[instr.rs] & instr.imm

    def xori(self, instr):
        self.cpu.rf[instr.rt] = self.cpu.rf[instr.rs] ^ instr.imm

    def jal(self, instr):
        self.cpu.rf[31] = self.cpu.pc+8
        self.cpu.pc = ((self.cpu.pc&0xf0000000) | (instr.target<<2))
        return 1

    def ble(self, instr):
        if self.to_signed(self.cpu.rf[instr.rs],32)<=self.to_signed(self.cpu.rf[instr.rt],32):
            self.cpu.pc = self.cpu.pc + 4 + self.to_signed(instr.imm,16)*4
            return 1

    def blt(self, instr):
        if self.to_signed(self.cpu.rf[instr.rs], 32) < self.to_signed(self.cpu.rf[instr.rt], 32):
            self.cpu.pc = self.cpu.pc + 4 + self.to_signed(instr.imm, 16)*4
            return 1

    def bgt(self, instr):
        if self.to_signed(self.cpu.rf[instr.rs],32)>self.to_signed(self.cpu.rf[instr.rt],32):
            self.cpu.pc = self.cpu.pc + 4 + self.to_signed(instr.imm,16)*4
            return 1

    def beql(self, instr):
        if self.cpu.rf[instr.rs]==self.cpu.rf[instr.rt]:
            self.cpu.pc = self.cpu.pc + 4 + self.to_signed(instr.imm,16)*4
            return 1
        else:
            return 2

    def bnel(self, instr):
        if self.cpu.rf[instr.rs]!=self.cpu.rf[instr.rt]:
            self.cpu.pc = self.cpu.pc + 4 + self.to_signed(instr.imm,16)*4
            return 1
        else:
            return 2

    def j(self, instr):
        self.cpu.pc = (self.cpu.pc&0xf0000000) | (instr.target<<2)
        return 1

    def swr(self, instr):
        #global bigendian
        addr = self.cpu.rf[instr.rs]+self.to_signed(instr.imm,16)
        index = addr&3
        base = addr&0xfffffffc
        if bigendian:
            self.cpu.mem.Write(base,(self.cpu.mem.Read(base,self.cpu.pc)&(0xffffffff>>((1+index)*8)))|(self.cpu.rf[instr.rt]<<((3-index)*8)),self.cpu.pc)
        else:
            self.cpu.mem.Write(base,(self.cpu.mem.Read(base,self.cpu.pc)&(0xffffffff>>((4-index)*8)))|(self.cpu.rf[instr.rt]&(0xffffffff<<(index*8))),self.cpu.pc)

    def swl(self, instr):
        #global bigendian
        addr = self.cpu.rf[instr.rs]+self.to_signed(instr.imm,16)
        index = addr&3
        base = addr&0xfffffffc
        if bigendian:
            self.cpu.mem.Write(base,(self.cpu.mem.Read(base,self.cpu.pc)&(0xffffffff<<(index*8)))|(self.cpu.rf[instr.rt]>>(index*8)),self.cpu.pc)
        else:
            self.cpu.mem.Write(base,(self.cpu.mem.Read(base,self.cpu.pc)&(0xffffffff<<((1+index)*8)))|(self.cpu.rf[instr.rt]>>((3-index)*8)),self.cpu.pc)

    def lwr(self, instr):
        #global bigendian
        addr = self.cpu.rf[instr.rs]+self.to_signed(instr.imm,16)
        index = addr&3
        base = addr&0xfffffffc
        if bigendian:
            self.cpu.rf[instr.rt] = (self.cpu.rf[instr.rt] & (0xffffffff<<((1+index)*8))) | (self.cpu.mem.Read(base,self.cpu.pc) >> ((3-index)*8))
        else:
            self.cpu.rf[instr.rt] = (self.cpu.rf[instr.rt] & (0xffffffff<<((4-index)*8))) | (self.cpu.mem.Read(base,self.cpu.pc) & (0xffffffff>>(index*8)))

    def lwl(self, instr):
        #global bigendian
        addr = self.cpu.rf[instr.rs]+self.to_signed(instr.imm,16)
        index = addr&3
        base = addr&0xfffffffc
        if bigendian:
            self.cpu.rf[instr.rt] = (self.cpu.rf[instr.rt] & (0xffffffff>>((4-index)*8))) | (self.cpu.mem.Read(base,self.cpu.pc)<<(index*8))
        else:
            self.cpu.rf[instr.rt] = (self.cpu.rf[instr.rt] & (0xffffffff>>((index+1)*8))) | (self.cpu.mem.Read(base,self.cpu.pc) & (0xffffffff<<((index+1)*8)))

    def cop0(self, instr):
        if instr.rs == 4:  # MTC0
            self.cpu.cop0_rf[instr.rd] = self.cpu.rf[instr.rt]
        elif instr.rs == 0:  # MFC0
            self.cpu.rf[instr.rt] = self.cpu.cop0_rf[instr.rd]
        else:
            self.logger.error('Illegal rs for cop0')

    def cop1(self, instr):
        if instr.rs == 4:  # MTC1
            self.cpu.cop1_rf[instr.rd] = self.cpu.rf[instr.rt]
        elif instr.rs == 0:  # MFC1
            self.cpu.rf[instr.rt] = self.cpu.cop1_rf[instr.rd]
        else:
            self.logger.error('Illegal rs for cop1')

    def cop2(self, instr):
        if instr.rs == 4:  # MTC2
            self.cpu.cop2_rf[instr.rd] = self.cpu.rf[instr.rt]
        elif instr.rs == 0:  # MFC2
            self.cpu.rf[instr.rt] = self.cpu.cop2_rf[instr.rd]
        else:
            self.logger.error('Illegal rs for cop2')

    def cop3(self, instr):
        if instr.rs == 4:  # MTC3
            self.cpu.cop3_rf[instr.rd] = self.cpu.rf[instr.rt]
        elif instr.rs == 0:  # MFC3
            self.cpu.rf[instr.rt] = self.cpu.cop3_rf[instr.rd]
        else:
            self.logger.error('Illegal rs for cop3')

    def cache(self, cache):
        pass

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='MISS - MIPS32 Instruction Set Simulator 0.1')
    parser.add_argument('-v', '--verbose', help='Verbose output', action='store_true')
    parser.add_argument('-f', '--file', required=True, help='ELF file')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO)

    miss = Miss(args)
    miss.execute()

