#include <unicorn/unicorn.h>
#include <string.h>
#include <libelf.h>
#include <gelf.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>

#define CODE_ADDR 0x1000
#define CODE_SIZE (1024)
#define DATA_ADDR 0x10000
#define DATA_SIZE (1024*64)

struct text {
	int		size;
	unsigned long	vaddr;
	char 		*buf;
};

int getText(char *fn, struct text *t){
	Elf *e;
	Elf_Kind ek;
	GElf_Ehdr ehdr;
	GElf_Phdr phdr;
	int fd, fd2;
	long unsigned int n;

	t->buf=NULL;
	if (elf_version(EV_CURRENT)==EV_NONE){
		printf("libelf error\n");
		return 0;
		}
	if ((fd=open(fn, O_RDONLY, 0))<0){
		printf("fn open error\n");
		return 0;
		}
	if ((e=elf_begin(fd, ELF_C_READ, NULL)) == NULL ){
		printf("libelf error\n");
		return 0;
		}
	ek=elf_kind(e);
	if (elf_kind(e) != ELF_K_ELF){
		printf("elf error\n");
		return 0;
		}
	if (gelf_getehdr(e, &ehdr) == NULL){
		printf("elf error\n");
		return 0;
		}
	if ((gelf_getclass(e)) == ELFCLASSNONE) {
		printf("elf error\n");
		return 0;
		}
	if ((elf_getident(e, NULL)) == NULL ) {
		printf("elf error\n");
		return 0;
		}
	if (elf_getphdrnum(e, &n ) != 0) {
		printf("elf error\n");
		return 0;
		}
	for ( int i = 0; i < n ; i ++) {
		if (gelf_getphdr (e, i, &phdr) != &phdr){
			printf("elf phdr error\n");
			return 0;
			}
		if (phdr.p_flags&1!=0) break;
		}
		printf("Type=%d, vaddr=%08lx, offset=%ld, size=%ld, flags=%d\n", phdr.p_type, phdr.p_vaddr, phdr.p_offset, phdr.p_filesz, phdr.p_flags);
	t->vaddr=phdr.p_vaddr;
	t->size=phdr.p_filesz;
	t->buf=(char *)malloc(phdr.p_filesz);
	if (t->buf == NULL) {
		printf("mem error\n");
		return 0;
		}
	if ((fd2=open(fn, O_RDONLY, 0))<0){
                printf("fn open error\n");
                return 0;
                }
	if (read(fd2, t->buf, phdr.p_filesz)!=phdr.p_filesz){
		printf("file read error\n");
                return 0;
                }


	(void) close(fd2);

	(void) elf_end(e);
	(void) close(fd);
	return 1;
}
void check(struct text *t){
	uint32_t *code=0;

	code=(uint32_t *)t->buf;
	for (int i=0; i<(t->size >> 2); i++){
		if (*code==0xd4000001) {
			printf("found @0x%08lx\n",t->vaddr+(i<<2));
			}
		printf("0x%08lx: 0x%04x\n", t->vaddr+(i<<2), *code);
		code++;
		}
}
int main(int argc, char **argv, char **envp){

	uc_engine *uc;
	uc_err err;
//	uint64_t x[30]={	0,0,0,0,0,0,0,0,
//				0,0,0,0,0,0,0,0,
//				0,0,0,0,0,0,0,0,
//				0,0,0,0,0,0,0,0
//				};
	uint64_t	x8, sp, pc;
	int		size;
	struct text	t;

	unsigned char shellcode[] = {
		0x1f, 0x20, 0x03, 0xd5,	//nop
		0x28, 0x10, 0x80, 0xd2,	//mov x8, 0x81
		0x01, 0x00, 0x00, 0xd4	//svc 0
		};
	if (!getText("glibc-2.34-39.el9.aarch64_libc.so.6", &t)) {
		printf("error\n");
		exit(-1);
		}
	check(&t);
	err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
	if (err) {
		printf("Failed on uc_open() with error returned: %u (%s)\n", err, uc_strerror(err));
		return -1;
		}

	uc_mem_map(uc, CODE_ADDR, CODE_SIZE, UC_PROT_ALL);
	uc_mem_map(uc, DATA_ADDR, DATA_SIZE, UC_PROT_ALL);
	uc_mem_write(uc, CODE_ADDR, shellcode, sizeof(shellcode) - 1);

	sp = DATA_ADDR+DATA_SIZE;
	uc_reg_write(uc, UC_ARM64_REG_SP, &sp);
//	uc_reg_write(uc, UC_ARM64_REG_X0, &x[0]);
//	uc_reg_write(uc, UC_ARM64_REG_X1, &x[1]);
//	uc_reg_write(uc, UC_ARM64_REG_X2, &x[2]);
//	uc_reg_write(uc, UC_ARM64_REG_X3, &x[3]);
//	uc_reg_write(uc, UC_ARM64_REG_X4, &x[4]);
//	uc_reg_write(uc, UC_ARM64_REG_X5, &x[5]);
//	uc_reg_write(uc, UC_ARM64_REG_X6, &x[6]);
//	uc_reg_write(uc, UC_ARM64_REG_X7, &x[7]);
//	uc_reg_write(uc, UC_ARM64_REG_X8, &x[8]);
//	uc_reg_write(uc, UC_ARM64_REG_X9, &x[9]);
//	uc_reg_write(uc, UC_ARM64_REG_X10, &x[10]);
//	uc_reg_write(uc, UC_ARM64_REG_X11, &x[11]);
//	uc_reg_write(uc, UC_ARM64_REG_X12, &x[12]);
//	uc_reg_write(uc, UC_ARM64_REG_X13, &x[13]);
//	uc_reg_write(uc, UC_ARM64_REG_X14, &x[14]);
//	uc_reg_write(uc, UC_ARM64_REG_X15, &x[15]);
//	uc_reg_write(uc, UC_ARM64_REG_X16, &x[16]);
//	uc_reg_write(uc, UC_ARM64_REG_X17, &x[17]);
//	uc_reg_write(uc, UC_ARM64_REG_X18, &x[18]);
//	uc_reg_write(uc, UC_ARM64_REG_X19, &x[19]);
//	uc_reg_write(uc, UC_ARM64_REG_X20, &x[20]);
//	uc_reg_write(uc, UC_ARM64_REG_X21, &x[21]);
//	uc_reg_write(uc, UC_ARM64_REG_X22, &x[22]);
//	uc_reg_write(uc, UC_ARM64_REG_X23, &x[23]);
//	uc_reg_write(uc, UC_ARM64_REG_X24, &x[24]);
//	uc_reg_write(uc, UC_ARM64_REG_X25, &x[25]);
//	uc_reg_write(uc, UC_ARM64_REG_X26, &x[26]);
//	uc_reg_write(uc, UC_ARM64_REG_X27, &x[27]);
//	uc_reg_write(uc, UC_ARM64_REG_X28, &x[28]);
//	uc_reg_write(uc, UC_ARM64_REG_X29, &x[29]);
//	uc_reg_write(uc, UC_ARM64_REG_X30, &x[30]);

	err = uc_emu_start(uc, CODE_ADDR, CODE_ADDR+sizeof(shellcode)-1, 0, 0);
	if (err) {
		printf("Failed on uc_emu_start() with error returned: %u(%s)\n", err, uc_strerror(err));
		}

	uc_reg_read(uc, UC_ARM64_REG_X8, &x8);
	uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
	printf("x8=%08lx, pc=%08lx\n",x8, pc);

	uc_close(uc);
	return 0;
}
