// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This code was translated into a form compatible with 6a from the public
// domain sources in SUPERCOP: http://bench.cr.yp.to/supercop.html

// func cswap(inout *[5]uint64, v uint64)
TEXT ·cswap(SB),7,$0
	MOVQ inout+0(FP),DI
	MOVQ v+8(FP),SI

	CMPQ SI,$1
	MOVQ 0(DI),SI
	MOVQ 80(DI),DX
	MOVQ 8(DI),CX
	MOVQ 88(DI),R8
	MOVQ SI,R9
	CMOVQEQ DX,SI
	CMOVQEQ R9,DX
	MOVQ CX,R9
	CMOVQEQ R8,CX
	CMOVQEQ R9,R8
	MOVQ SI,0(DI)
	MOVQ DX,80(DI)
	MOVQ CX,8(DI)
	MOVQ R8,88(DI)
	MOVQ 16(DI),SI
	MOVQ 96(DI),DX
	MOVQ 24(DI),CX
	MOVQ 104(DI),R8
	MOVQ SI,R9
	CMOVQEQ DX,SI
	CMOVQEQ R9,DX
	MOVQ CX,R9
	CMOVQEQ R8,CX
	CMOVQEQ R9,R8
	MOVQ SI,16(DI)
	MOVQ DX,96(DI)
	MOVQ CX,24(DI)
	MOVQ R8,104(DI)
	MOVQ 32(DI),SI
	MOVQ 112(DI),DX
	MOVQ 40(DI),CX
	MOVQ 120(DI),R8
	MOVQ SI,R9
	CMOVQEQ DX,SI
	CMOVQEQ R9,DX
	MOVQ CX,R9
	CMOVQEQ R8,CX
	CMOVQEQ R9,R8
	MOVQ SI,32(DI)
	MOVQ DX,112(DI)
	MOVQ CX,40(DI)
	MOVQ R8,120(DI)
	MOVQ 48(DI),SI
	MOVQ 128(DI),DX
	MOVQ 56(DI),CX
	MOVQ 136(DI),R8
	MOVQ SI,R9
	CMOVQEQ DX,SI
	CMOVQEQ R9,DX
	MOVQ CX,R9
	CMOVQEQ R8,CX
	CMOVQEQ R9,R8
	MOVQ SI,48(DI)
	MOVQ DX,128(DI)
	MOVQ CX,56(DI)
	MOVQ R8,136(DI)
	MOVQ 64(DI),SI
	MOVQ 144(DI),DX
	MOVQ 72(DI),CX
	MOVQ 152(DI),R8
	MOVQ SI,R9
	CMOVQEQ DX,SI
	CMOVQEQ R9,DX
	MOVQ CX,R9
	CMOVQEQ R8,CX
	CMOVQEQ R9,R8
	MOVQ SI,64(DI)
	MOVQ DX,144(DI)
	MOVQ CX,72(DI)
	MOVQ R8,152(DI)
	MOVQ DI,AX
	MOVQ SI,DX
	RET
