#include "coctx.h"
#include <string.h>

enum
{
	kEIP = 0,
	kESP = 7,
};

//-------------
//// 64 bit
////low | regs[0]: r15 |
////    | regs[1]: r14 |
////    | regs[2]: r13 |
////    | regs[3]: r12 |
////    | regs[4]: r9  |
////    | regs[5]: r8  |
////    | regs[6]: rbp |
////    | regs[7]: rdi |
////    | regs[8]: rsi |
////    | regs[9]: ret |  //ret func addr
////    | regs[10]: rdx |
////    | regs[11]: rcx |
////    | regs[12]: rbx |
////hig | regs[13]: rsp |
enum
{
	kRDI = 7,
	kRSI = 8,
	kRETAddr = 9,
	kRSP = 13,
};

//64 bit
extern "C"
{
	extern void coctx_swap( coctx_t *,coctx_t* ) asm("coctx_swap");
};
int coctx_make( coctx_t *ctx,coctx_pfn_t pfn,const void *s,const void *s1 )
{
	char *sp = ctx->ss_sp + ctx->ss_size;
	sp = (char*) ((unsigned long)sp & -16LL  );

	memset(ctx->regs, 0, sizeof(ctx->regs));

	ctx->regs[ kRSP ] = sp - 8;

	ctx->regs[ kRETAddr] = (char*)pfn;

	ctx->regs[ kRDI ] = (char*)s;
	ctx->regs[ kRSI ] = (char*)s1;
	return 0;
}

int coctx_init( coctx_t *ctx )
{
	memset( ctx,0,sizeof(*ctx));
	return 0;
}