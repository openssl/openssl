/* incore_macho.c */
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* ====================================================================
 * Copyright 2011 Thursby Software Systems, Inc. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Thursby Software Systems, Inc and is licensed pursuant to the OpenSSL
 * open source license.
 *
 * The Contribution, originally written by Paul W. Nelson of
 * Thursby Software Systems, Inc, consists of the fingerprint calculation
 * required for the FIPS140 integrity check.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Thursby that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, THURSBY
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <stdio.h>
#include <ctype.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/stab.h>
#include <mach-o/reloc.h>
#include <mach-o/fat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/vmparam.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/fips.h>

#ifndef CPU_SUBRTPE_V7F
# define CPU_SUBRTPE_V7F	((cpu_subtype_t) 10)
#endif
/* iPhone 5 and iPad 4 (A6 Processors) */
#ifndef CPU_SUBTYPE_ARM_V7S
# define CPU_SUBTYPE_ARM_V7S	((cpu_subtype_t) 11)
#endif
#ifndef CPU_SUBTYPE_ARM_V7K
# define CPU_SUBTYPE_ARM_V7K	((cpu_subtype_t) 12)
#endif
#ifndef CPU_SUBTYPE_ARM_V8
# define CPU_SUBTYPE_ARM_V8	((cpu_subtype_t) 13)
#endif

#ifndef CPU_TYPE_ARM64
# define CPU_TYPE_ARM64	(CPU_TYPE_ARM | CPU_ARCH_ABI64)
#endif

static int gVerbosity = 0;

static void hexdump(const unsigned char *buf,size_t len,
                    unsigned long address,FILE* fp)
{
	unsigned long addr;
	int i;
	
	addr = 0;
	while(addr<len)
	{
		fprintf(fp,"%6.6lx - ",addr+address);
		for(i=0;i<16;i++)
		{
			if(addr+i<len)
				fprintf(fp,"%2.2x ",buf[addr+i]);
			else
				fprintf(fp,"   ");
		}
		fprintf(fp," \"");
		for(i=0;i<16;i++)
		{
			if(addr+i<len)
			{
				if(isprint(buf[addr+i]) && (buf[addr+i]<0x7e) )
					putc(buf[addr+i],fp);
				else
					putc('.',fp);
			}
		}
		fprintf(fp,"\"\n");
		addr += 16;
	}
	fflush(fp);
}

struct segment_rec;
typedef struct section_rec {
    char            sectname[16];
    char            segname[16];
    uint64_t        addr;
    uint64_t        size;
    uint32_t        offset;
    uint32_t        align;
    uint32_t        reloff;
    uint32_t        nreloc;
    uint32_t        flags;
    struct segment_rec* segment;
    struct section_rec* _next;
} section_t;

typedef struct segment_rec {
    char            segname[16];
    uint64_t        vmaddr;
    uint64_t        vmsize;
    off_t           fileoff;
    uint64_t        filesize;
    vm_prot_t       maxprot;
    vm_prot_t       initprot;
    uint32_t        nsects;
    uint32_t        flags;
    unsigned char*  mapped;
    struct segment_rec* _next;
} segment_t;

typedef struct symtab_entry_rec {
    uint32_t        n_strx;
    uint8_t         n_type;
    uint8_t         n_sect;
    int16_t         n_desc;
    uint64_t        n_value;
    const char *    n_symbol;
    section_t*      section;
    unsigned char*  mapped;     /* pointer to the actual data in mapped file */
    struct symtab_entry_rec*    _next;
} symtab_entry_t;


typedef struct macho_file_rec
{
    const char *    filename;
    void*           mapped;
    size_t          size;       /* number of valid bytes at 'mapped' */
    uint32_t        align;      /* byte alignment for this arch */
    int             isBigEndian;/* 1 if everything is byte swapped */
    
    cpu_type_t      cpu_type;
    cpu_subtype_t   cpu_subtype;
    section_t*      sec_head;
    section_t*      sec_tail;
    
    segment_t*      seg_head;
    segment_t*      seg_tail;
    
    symtab_entry_t* sym_head;
    symtab_entry_t* sym_tail;
    struct macho_file_rec   *next;
    char *          fingerprint_computed;
    char *          fingerprint_original;
    
} macho_file_t;

static const char *cputype(cpu_type_t cputype, cpu_subtype_t subtype)
{
    const char *rval = "unknown";
    switch( cputype )
    {
        case CPU_TYPE_I386: rval = "i386"; break;
        case CPU_TYPE_X86_64: rval = "x86_64"; break;
        case CPU_TYPE_ARM64: rval = "aarch64"; break;
        case CPU_TYPE_ARM:
        {
            switch( subtype )
            {
                case CPU_SUBTYPE_ARM_V6:    rval = "armv6"; break;
                case CPU_SUBTYPE_ARM_V7:    rval = "armv7"; break;
                case CPU_SUBTYPE_ARM_V7S:   rval = "armv7s"; break;
                case CPU_SUBTYPE_ARM_V7K:   rval = "armv7k"; break;
                case CPU_SUBTYPE_ARM_V8:    rval = "armv8"; break;
                default: rval = "arm"; break;
            }
        }
    }
    return rval;
}

static void *add_section( macho_file_t *macho, void *pCommand,
                         uint8_t is64bit, struct segment_rec *segment )
{
    void* rval = 0;
    uint32_t flags;
    
    section_t* sec = (section_t*)calloc(1, sizeof(section_t));
    if(!sec) return NULL;
    
    if(is64bit)
    {
        struct section_64* pSec = (struct section_64*)pCommand;
        flags = pSec->flags;
        memcpy( sec->sectname, pSec->sectname, 16 );
        memcpy( sec->segname, pSec->segname, 16 );
        sec->addr = pSec->addr;
        sec->size = pSec->size;
        sec->offset = pSec->offset;
        sec->align = pSec->align;
        sec->reloff = pSec->reloff;
        sec->nreloc = pSec->nreloc;
        sec->flags = pSec->flags;
        rval = pCommand + sizeof(struct section_64);
    }
    else
    {
        struct section* pSec = (struct section*)pCommand;
        flags = pSec->flags;
        memcpy( sec->sectname, pSec->sectname, 16 );
        memcpy( sec->segname, pSec->segname, 16 );
        sec->addr = pSec->addr;
        sec->size = pSec->size;
        sec->offset = pSec->offset;
        sec->align = pSec->align;
        sec->reloff = pSec->reloff;
        sec->nreloc = pSec->nreloc;
        sec->flags = pSec->flags;
        rval = pCommand + sizeof(struct section);
    }
    if( gVerbosity > 2 )
        fprintf(stderr, "  flags=%x\n", flags);
    sec->segment = segment;
    sec->_next = NULL;
    if( macho->sec_head )
        macho->sec_tail->_next = sec;
    else
        macho->sec_head = sec;
    macho->sec_tail = sec;
    return rval;
}

static section_t *lookup_section(macho_file_t* macho, uint32_t nsect)
{
    section_t *rval = macho->sec_head;
    
    if(nsect == 0) return NULL;
    
    while( rval != NULL && --nsect > 0 )
        rval = rval->_next;
    return rval;
}

static void *add_segment( macho_file_t *macho, void *pCommand, uint8_t is64bit )
{
    void *rval = 0;
    segment_t *seg = (segment_t *)calloc(1, sizeof(segment_t));
    
    if(!seg)
        return 0;
    if(is64bit)
    {
        struct segment_command_64 *pSeg = (struct segment_command_64*)pCommand;
        
        memcpy( seg->segname, pSeg->segname, 16 );
        seg->vmaddr = pSeg->vmaddr;
        seg->vmsize = pSeg->vmsize;
        seg->fileoff = pSeg->fileoff;
        seg->filesize = pSeg->filesize;
        seg->maxprot = pSeg->maxprot;
        seg->initprot = pSeg->initprot;
        seg->nsects = pSeg->nsects;
        seg->flags = pSeg->flags;
        rval = pCommand + sizeof(struct segment_command_64);
    } else {
        struct segment_command *pSeg = (struct segment_command*)pCommand;
        
        memcpy( seg->segname, pSeg->segname, 16 );
        seg->vmaddr = pSeg->vmaddr;
        seg->vmsize = pSeg->vmsize;
        seg->fileoff = pSeg->fileoff;
        seg->filesize = pSeg->filesize;
        seg->maxprot = pSeg->maxprot;
        seg->initprot = pSeg->initprot;
        seg->nsects = pSeg->nsects;
        seg->flags = pSeg->flags;
        rval = pCommand + sizeof(struct segment_command);
    }
    seg->_next = NULL;
    seg->mapped = macho->mapped + seg->fileoff;
    
    if( macho->seg_head )
        macho->seg_tail->_next = seg;
    else
        macho->seg_head = seg;
    macho->seg_tail = seg;
    
    if( gVerbosity > 2 )
        fprintf(stderr, "Segment %s: flags=%x\n", seg->segname, seg->flags );
    
    unsigned int ii;
    for( ii=0; ii<seg->nsects; ii++ )
    {
        rval = add_section(macho, rval, is64bit, seg);
    }
    return rval;
}

static const char *type_str(uint8_t n_type)
{
    static char result[16] = {};
    int idx = 0;
    uint8_t stab;
    
    memset(result, 0, sizeof(result));
    if( n_type & N_PEXT )
        result[idx++] = 'P';
    if( n_type & N_EXT )
        result[idx++] = 'E';
    if( idx > 0 )
        result[idx++] = ':';
    switch( n_type & N_TYPE )
    {
        case N_UNDF: result[idx++] = 'U'; break;
        case N_ABS: result[idx++] = 'A'; break;
        case N_PBUD: result[idx++] = 'P'; break;
        case N_SECT: result[idx++] = 'S'; break;
        case N_INDR: result[idx++] = 'I'; break;
        default: result[idx++] = '*'; break;
    }
    stab = n_type & N_STAB;
    if( stab )
    {
        result[idx++] = ':';
        result[idx++] = '0'+(stab >> 5);
    }
    result[idx++] = 0;
    return result;
}

static symtab_entry_t *lookup_entry_by_name( macho_file_t *macho,
                                            const char *name)
{
    symtab_entry_t *entry;
    
    for( entry = macho->sym_head; entry; entry = entry->_next )
    {
        if(strcmp(entry->n_symbol,name)==0 && (entry->n_type & N_STAB)==0 )
        {
            if( entry->section == NULL )
            {
                entry->section = lookup_section( macho, entry->n_sect );
                if( entry->section )
                {
                    section_t* sec = entry->section;
                    segment_t* seg = sec->segment;
                    uint64_t offset = entry->n_value - seg->vmaddr;
                    
                    entry->mapped = seg->mapped+offset;
                }
                else
                    entry = 0;
            }
            break;
        }
    }
    return entry;
}

static void check_symtab(macho_file_t *macho,void *pCommand,uint8_t is64bit )
{
    
    struct symtab_command *pSym = (struct symtab_command *)pCommand;
    void *pS = macho->mapped + pSym->symoff;
    unsigned int ii = 0;
    
    /* collect symbols */
    for( ii=0; ii<pSym->nsyms; ii++ )
    {
        struct nlist *pnlist=(struct nlist*)pS;
        symtab_entry_t *entry=(symtab_entry_t*)calloc(1,sizeof(symtab_entry_t));
        
        if(!entry)
        {
            fprintf(stderr, "out of memory!\n");
            _exit(1);
        }
        entry->n_strx = pnlist->n_un.n_strx;
        entry->n_type = pnlist->n_type;
        entry->n_sect = pnlist->n_sect;
        entry->n_desc = pnlist->n_desc;
        entry->section = NULL;
        if(is64bit)
        {
            struct nlist_64 *pnlist64 = (struct nlist_64*)pS;
            
            entry->n_value = pnlist64->n_value;
            pS += sizeof(struct nlist_64);
        }
        else
        {
            entry->n_value = pnlist->n_value;
            pS += sizeof(struct nlist);
        }
        entry->n_symbol=(const char *)macho->mapped+pSym->stroff+entry->n_strx;
        entry->_next = NULL;
        if( macho->sym_head )
            macho->sym_tail->_next = entry;
        else
            macho->sym_head = entry;
        macho->sym_tail = entry;
    }
    if( gVerbosity > 2 )
    {
        /* dump info */
        symtab_entry_t* entry;
        
        for( entry = macho->sym_head; entry; entry=entry->_next )
        {
            /* only do non-debug symbols */
            if( (entry->n_type & N_STAB) == 0 )
                fprintf(stderr, "%32.32s %18llx type=%s, sect=%d\n",
                        entry->n_symbol, entry->n_value,
                        type_str(entry->n_type), entry->n_sect);
        }
    }
}

static int load_architecture( macho_file_t* inFile )
{
    /* check the header */
    unsigned int ii;
    void * pCurrent = inFile->mapped;
    struct mach_header* header = (struct mach_header*)pCurrent;
    
    if( header->magic != MH_MAGIC && header->magic != MH_MAGIC_64 )
    {
        fprintf(stderr, "%s is not a mach-o file\n", inFile->filename);
        return -1;
    }
    else if( header->filetype == MH_BUNDLE )
    {
        fprintf(stderr, "%s is not a mach-o executable file (filetype MH_BUNDLE, should be MH_EXECUTE or MH_DYLIB)\n", inFile->filename);
        return -1;
    }
    else if( header->filetype == MH_DYLINKER )
    {
        fprintf(stderr, "%s is not a mach-o executable file (filetype MH_DYLINKER, should be MH_EXECUTE or MH_DYLIB)\n", inFile->filename);
        return -1;
    }
    else if( !(header->filetype == MH_EXECUTE || header->filetype == MH_DYLIB) )
    {
        fprintf(stderr, "%s is not a mach-o executable file (filetype %d, should be MH_EXECUTE or MH_DYLIB)\n", inFile->filename, header->filetype);
        return -1;
    }
    
    if( gVerbosity > 1 )
        fprintf(stderr, "loading %s(%s)\n", inFile->filename, cputype(header->cputype, header->cpusubtype));
    
    inFile->cpu_type = header->cputype;
    inFile->cpu_subtype = header->cpusubtype;
    
    if( header->magic == MH_MAGIC )
        pCurrent += sizeof( struct mach_header );
    else if( header->magic == MH_MAGIC_64 )
        pCurrent += sizeof( struct mach_header_64 );
    for( ii=0; ii<header->ncmds; ii++ )
    {
        struct load_command* command = (struct load_command*)pCurrent;
        const char * lc_name;
        
        switch( command->cmd )
        {
            case LC_SEGMENT:
            {
                lc_name = "LC_SEGMENT";
                add_segment(inFile, pCurrent, header->magic == MH_MAGIC_64);
                break;
            }
            case LC_SYMTAB:
            {
                lc_name = "LC_SYMTAB";
                check_symtab(inFile, pCurrent, header->magic == MH_MAGIC_64 );
                break;
            }
            case LC_SYMSEG: lc_name = "LC_SYMSEG"; break;
            case LC_THREAD: lc_name = "LC_THREAD"; break;
            case LC_UNIXTHREAD: lc_name = "LC_UNIXTHREAD"; break;
            case LC_LOADFVMLIB: lc_name = "LC_LOADFVMLIB"; break;
            case LC_IDFVMLIB: lc_name = "LC_IDFVMLIB"; break;
            case LC_IDENT: lc_name = "LC_IDENT"; break;
            case LC_FVMFILE: lc_name = "LC_FVMFILE"; break;
            case LC_PREPAGE: lc_name = "LC_PREPAGE"; break;
            case LC_DYSYMTAB: lc_name = "LC_DYSYMTAB"; break;
            case LC_LOAD_DYLIB: lc_name = "LC_LOAD_DYLIB"; break;
            case LC_ID_DYLIB: lc_name = "LC_ID_DYLIB"; break;
            case LC_LOAD_DYLINKER: lc_name = "LC_LOAD_DYLINKER"; break;
            case LC_ID_DYLINKER: lc_name = "LC_ID_DYLINKER"; break;
            case LC_PREBOUND_DYLIB: lc_name = "LC_PREBOUND_DYLIB"; break;
            case LC_ROUTINES: lc_name = "LC_ROUTINES"; break;
            case LC_SUB_FRAMEWORK: lc_name = "LC_SUB_FRAMEWORK"; break;
            case LC_SUB_UMBRELLA: lc_name = "LC_SUB_UMBRELLA"; break;
            case LC_SUB_CLIENT: lc_name = "LC_SUB_CLIENT"; break;
            case LC_SUB_LIBRARY: lc_name = "LC_SUB_LIBRARY"; break;
            case LC_TWOLEVEL_HINTS: lc_name = "LC_TWOLEVEL_HINTS"; break;
            case LC_PREBIND_CKSUM: lc_name = "LC_PREBIND_CKSUM"; break;
            case LC_LOAD_WEAK_DYLIB: lc_name = "LC_LOAD_WEAK_DYLIB"; break;
            case LC_SEGMENT_64:
            {
                lc_name = "LC_SEGMENT_64";
                add_segment(inFile, pCurrent, TRUE);
                break;
            }
            case LC_ROUTINES_64: lc_name = "LC_ROUTINES_64"; break;
            case LC_UUID: lc_name = "LC_UUID"; break;
            case LC_RPATH: lc_name = "LC_RPATH"; break;
            case LC_CODE_SIGNATURE: lc_name = "LC_CODE_SIGNATURE"; break;
            case LC_SEGMENT_SPLIT_INFO:
                lc_name = "LC_SEGMENT_SPLIT_INFO"; break;
            case LC_REEXPORT_DYLIB: lc_name = "LC_REEXPORT_DYLIB"; break;
            case LC_LAZY_LOAD_DYLIB: lc_name = "LC_LAZY_LOAD_DYLIB"; break;
            case LC_ENCRYPTION_INFO: lc_name = "LC_ENCRYPTION_INFO"; break;
            case LC_DYLD_INFO: lc_name = "LC_DYLD_INFO"; break;
            case LC_DYLD_INFO_ONLY: lc_name = "LC_DYLD_INFO_ONLY"; break;
            case LC_LOAD_UPWARD_DYLIB: lc_name = "LC_LOAD_UPWARD_DYLIB"; break;
            case LC_VERSION_MIN_MACOSX:
                lc_name = "LC_VERSION_MIN_MACOSX"; break;
            case LC_VERSION_MIN_IPHONEOS:
                lc_name = "LC_VERSION_MIN_IPHONEOS"; break;
            case LC_FUNCTION_STARTS: lc_name = "LC_FUNCTION_STARTS"; break;
            case LC_DYLD_ENVIRONMENT: lc_name = "LC_DYLD_ENVIRONMENT"; break;
            default: lc_name=NULL; break;
        }
        if( gVerbosity > 1 )
        {
            if(lc_name)
                fprintf(stderr,"command %s: size=%d\n",lc_name,
						command->cmdsize );
            else
                fprintf(stderr,"command %x, size=%d\n",command->cmd,
						command->cmdsize);
        }
        pCurrent += command->cmdsize;
    }
    return 0;
}

#define HOSTORDER_VALUE(val) (isBigEndian ? OSSwapBigToHostInt32(val) : (val))

static macho_file_t *load_file(macho_file_t *inFile)
{
    macho_file_t *rval = NULL;
    void *pCurrent = inFile->mapped;
    struct fat_header *fat = (struct fat_header *)pCurrent;
    
    if( fat->magic==FAT_MAGIC || fat->magic==FAT_CIGAM )
    {
        int isBigEndian = fat->magic == FAT_CIGAM;
        unsigned int ii = 0;
        struct fat_arch *pArch = NULL;
        uint32_t nfat_arch = 0;
        
        pCurrent += sizeof(struct fat_header);
        pArch = pCurrent;
        nfat_arch = HOSTORDER_VALUE(fat->nfat_arch);
        for( ii=0; ii<nfat_arch; ii++)
        {
            macho_file_t *archfile=(macho_file_t *)calloc(1,
                                                          sizeof(macho_file_t));
            if( archfile )
            {
                archfile->filename = strdup(inFile->filename);
                archfile->mapped = inFile->mapped +
                HOSTORDER_VALUE(pArch->offset);
                archfile->size = HOSTORDER_VALUE(pArch->size);
                archfile->align = HOSTORDER_VALUE(pArch->align);
                archfile->isBigEndian = isBigEndian;
                archfile->cpu_type = HOSTORDER_VALUE(pArch->cputype);
                archfile->cpu_subtype = HOSTORDER_VALUE(pArch->cpusubtype);
                if( load_architecture(archfile) == 0 )
                {
                    archfile->next = rval;
                    rval = archfile;
                }
            }
            else
                return NULL;    /* no memory */
            pArch++;
        }
    }
    else
    {
        struct mach_header* header = (struct mach_header*)pCurrent;
        
        if( header->magic != MH_MAGIC && header->magic != MH_MAGIC_64 )
        {
            fprintf(stderr, "%s is not a mach-o file\n", inFile->filename);
        }
        else if( header->filetype == MH_BUNDLE )
        {
            fprintf(stderr, "%s is not a mach-o executable file "
                    "(filetype MH_BUNDLE, should be MH_EXECUTE or MH_DYLIB)\n", inFile->filename);
        }
        else if( header->filetype == MH_DYLINKER )
        {
            fprintf(stderr, "%s is not a mach-o executable file "
                    "(filetype MH_DYLINKER, should be MH_EXECUTE or MH_DYLIB)\n", inFile->filename);
        }
        else if( !(header->filetype == MH_EXECUTE || header->filetype == MH_DYLIB) )
        {
            fprintf(stderr, "%s is not a mach-o executable file "
                    "(filetype %d should be MH_EXECUTE or MH_DYLIB)\n",
                    inFile->filename, header->filetype );
        }
        if( load_architecture(inFile) == 0 )
        {
            inFile->next = 0;
            rval = inFile;
        }
    }
    return rval;
}

#define FIPS_SIGNATURE_SIZE 20
#define FIPS_FINGERPRINT_SIZE 40

static void debug_symbol( symtab_entry_t* sym )
{
    if( gVerbosity > 1 )
    {
        section_t* sec = sym->section;
        segment_t* seg = sec->segment;
        fprintf(stderr, "%-40.40s: %llx sect=%s, segment=%s prot=(%x->%x)\n",
               	sym->n_symbol, sym->n_value, sec->sectname,
                seg->segname, seg->initprot, seg->maxprot );
    }
}

/*
 * Minimalistic HMAC from fips_standalone_sha1.c
 */
static void hmac_init(SHA_CTX *md_ctx,SHA_CTX *o_ctx,
		      const char *key)
    {
    size_t len=strlen(key);
    int i;
    unsigned char keymd[HMAC_MAX_MD_CBLOCK];
    unsigned char pad[HMAC_MAX_MD_CBLOCK];

    if (len > SHA_CBLOCK)
	{
	SHA1_Init(md_ctx);
	SHA1_Update(md_ctx,key,len);
	SHA1_Final(keymd,md_ctx);
	len=20;
	}
    else
	memcpy(keymd,key,len);
    memset(&keymd[len],'\0',HMAC_MAX_MD_CBLOCK-len);

    for(i=0 ; i < HMAC_MAX_MD_CBLOCK ; i++)
	pad[i]=0x36^keymd[i];
    SHA1_Init(md_ctx);
    SHA1_Update(md_ctx,pad,SHA_CBLOCK);

    for(i=0 ; i < HMAC_MAX_MD_CBLOCK ; i++)
	pad[i]=0x5c^keymd[i];
    SHA1_Init(o_ctx);
    SHA1_Update(o_ctx,pad,SHA_CBLOCK);
    }

static void hmac_final(unsigned char *md,SHA_CTX *md_ctx,SHA_CTX *o_ctx)
    {
    unsigned char buf[20];

    SHA1_Final(buf,md_ctx);
    SHA1_Update(o_ctx,buf,sizeof buf);
    SHA1_Final(md,o_ctx);
    }

static int fingerprint(macho_file_t* inFile, int addFingerprint)
{
    int rval = 0;
    unsigned char signature[FIPS_SIGNATURE_SIZE];
    char signature_string[FIPS_FINGERPRINT_SIZE+1];
    unsigned int len = sizeof(signature);
    const char *fingerprint = NULL;
    int ii = 0;
    
#define LOOKUP_SYMBOL( symname, prot ) \
  symtab_entry_t *symname = \
  lookup_entry_by_name( inFile, "_" #symname ); \
  if( ! symname ) { \
    fprintf(stderr, "%s: Not a FIPS executable (" \
    #symname " not found)\n", inFile->filename ); \
    return -1;\
  } \
  if( (symname->section->segment->initprot & \
    (PROT_READ|PROT_WRITE|PROT_EXEC)) != (prot) ) { \
      fprintf(stderr, #symname \
      " segment has the wrong protection.\n"); \
      debug_symbol(symname);return -1;\
  }
    
    LOOKUP_SYMBOL( FIPS_rodata_start, PROT_READ | PROT_EXEC );
    LOOKUP_SYMBOL( FIPS_rodata_end, PROT_READ | PROT_EXEC );
    LOOKUP_SYMBOL( FIPS_text_startX, PROT_READ | PROT_EXEC );
    LOOKUP_SYMBOL( FIPS_text_endX, PROT_READ | PROT_EXEC );
    LOOKUP_SYMBOL( FIPS_signature, PROT_WRITE | PROT_READ );
    LOOKUP_SYMBOL( FINGERPRINT_ascii_value, PROT_READ | PROT_EXEC );
    
    if( gVerbosity > 1 )
    {
        debug_symbol( FIPS_rodata_start );
        debug_symbol( FIPS_rodata_end );
        debug_symbol( FIPS_text_startX );
        debug_symbol( FIPS_text_endX );
        debug_symbol( FIPS_signature );
        debug_symbol( FINGERPRINT_ascii_value );
        
        fingerprint = (const char *)FINGERPRINT_ascii_value->mapped;
        fprintf(stderr, "fingerprint: ");
        for(ii=0; ii<40; ii++ )
        {
            if( fingerprint[ii] == 0 )
                break;
            putc(fingerprint[ii], stderr);
        }
        putc('\n', stderr);
    }
    
    /* check for the prefix ? character */
    {
        const unsigned char * p1 = FIPS_text_startX->mapped;
        const unsigned char * p2 = FIPS_text_endX->mapped;
        const unsigned char * p3 = FIPS_rodata_start->mapped;
        const unsigned char * p4 = FIPS_rodata_end->mapped;
        static const char          FIPS_hmac_key[]="etaonrishdlcupfm";
        SHA_CTX md_ctx,o_ctx;
        
	hmac_init(&md_ctx,&o_ctx,FIPS_hmac_key);
        
        if (p1<=p3 && p2>=p3)
            p3=p1, p4=p2>p4?p2:p4, p1=NULL, p2=NULL;
        else if (p3<=p1 && p4>=p1)
            p3=p3, p4=p2>p4?p2:p4, p1=NULL, p2=NULL;
        
        if (p1) {
            
            SHA1_Update(&md_ctx,p1,(size_t)p2-(size_t)p1);
        }
        if (FIPS_signature->mapped>=p3 && FIPS_signature->mapped<p4)
        {
            /* "punch" hole */
            SHA1_Update(&md_ctx,p3,(size_t)FIPS_signature-(size_t)p3);
            p3 = FIPS_signature->mapped+FIPS_SIGNATURE_SIZE;
            if (p3<p4) {
                SHA1_Update(&md_ctx,p3,(size_t)p4-(size_t)p3);
            }
        }
        else {
            SHA1_Update(&md_ctx,p3,(size_t)p4-(size_t)p3);
	}
        
        hmac_final(signature,&md_ctx,&o_ctx);
        
        {
            char *pString = NULL;
            unsigned int i = 0;
            
            memset( signature_string, 0, sizeof(signature_string));
            pString = signature_string;
            for (i=0;i<len;i++)
            {
                snprintf(pString, 3, "%02x",signature[i]);
                pString+=2;
            }
            *pString = 0;
        }
    }
    fingerprint = (char *)FINGERPRINT_ascii_value->mapped;
    inFile->fingerprint_original = strndup(fingerprint,FIPS_FINGERPRINT_SIZE);
    inFile->fingerprint_computed = strdup(signature_string);
    
    if( addFingerprint )
    {
        void *fp_page = NULL;
        void *fp_end = NULL;
        
        if(strcmp(fingerprint,"?have to make sure this string is unique")!=0)
        {
            if (memcmp((char*)fingerprint, signature_string, FIPS_FINGERPRINT_SIZE)!=0)
            {
                fprintf(stderr,
                        "%s(%s) original fingerprint incorrect: %s\n",
                        inFile->filename,
                        cputype(inFile->cpu_type, inFile->cpu_subtype),
                        fingerprint);
            }
        }

        fp_page = (void*)((uintptr_t)fingerprint & ~PAGE_MASK);
        fp_end = (void*)((uintptr_t)(fingerprint+(PAGE_SIZE*2)) & ~PAGE_MASK);
        if( mprotect( fp_page, fp_end-fp_page, PROT_READ|PROT_WRITE ) )
        {
            perror("Can't write the fingerprint - mprotect failed");
            fprintf(stderr, "fp_page=%p, fp_end=%p, len=%ld\n",
                    fp_page, fp_end, (size_t)(fp_end-fp_page));
            rval = 1;
        }
        else
        {
            memcpy((char*)fingerprint, signature_string, FIPS_FINGERPRINT_SIZE);
            if( msync(fp_page, (fp_end-fp_page), 0) )
                perror("msync failed");
        }
        if( gVerbosity > 0 )
            fprintf(stderr, "%s(%s) fingerprint: %s\n", inFile->filename,
                    cputype(inFile->cpu_type,inFile->cpu_subtype),
                    signature_string);
    }
    if( *fingerprint == '?' )
    {
        printf("%s(%s) has no fingerprint.\n", inFile->filename,
               cputype(inFile->cpu_type, inFile->cpu_subtype));
        rval = 2;
    }
    else if( strncmp( fingerprint, signature_string, FIPS_FINGERPRINT_SIZE) == 0 )
    {
        if( ! addFingerprint )
            printf("%s(%s) fingerprint is correct: %s\n", inFile->filename,
                   cputype(inFile->cpu_type, inFile->cpu_subtype),
                   signature_string);
    }
    else
    {
        printf("%s(%s) fingerprint %.40s is not correct\n", inFile->filename,
                   cputype(inFile->cpu_type,inFile->cpu_subtype), fingerprint);
        printf("calculated: %s\n", signature_string);
        rval = -1;
    }
    return rval;
}

static int make_fingerprint( const char * inApp, int addFingerprint )
{
    int rval = 1;
    int appfd = -1;
    if( addFingerprint )
        appfd = open( inApp, O_RDWR );
    if( appfd < 0 )
    {
        if( addFingerprint )
            fprintf(stderr, "Can't modify %s. Verifying only.\n", inApp);
        addFingerprint = 0;
        appfd = open( inApp, O_RDONLY );
    }
    if( appfd >= 0 )
    {
        struct stat stbuf;
        fstat(appfd, &stbuf);
        void * pApp = mmap(0, (size_t)stbuf.st_size, PROT_READ,
                           MAP_SHARED, appfd, (off_t)0);
        if( pApp == MAP_FAILED )
        {
            perror(inApp);
        }
        else
        {
            macho_file_t theFile;
            macho_file_t* architectures;
            macho_file_t* pArchitecture;
            
            memset( &theFile, 0, sizeof(theFile) );
            theFile.filename = inApp;
            theFile.mapped = pApp;
            architectures = load_file(&theFile);
            for( pArchitecture = architectures; pArchitecture;
                pArchitecture = pArchitecture->next )
            {
                rval = fingerprint(pArchitecture, addFingerprint);
                if( rval && addFingerprint )
                {
                    printf("Failure\n");
                    break;
                }
            }
            if((rval==0) && addFingerprint)
            {
                printf("Fingerprint Stored\n");
            }
            munmap(pApp, (size_t)stbuf.st_size);
        }
        close(appfd);
    }
    else
    {
        fprintf(stderr, "Can't open %s\n", inApp );
    }
    return rval;
}

static void print_usage(const char * prog)
{
    fprintf(stderr, "usage:\n\t%s [--debug] [--quiet] [-exe|-dso|-dylib] executable\n", prog);
    _exit(1);
}

int main (int argc, const char * argv[])
{
    const char * pname = argv[0];
    const char * filename = NULL;
    int addFingerprint = 1;
    const char * verbose_env = getenv("FIPS_SIG_VERBOSE");
    
    if( verbose_env )
        gVerbosity = atoi(verbose_env);
    
    if( gVerbosity < 0 )
        gVerbosity = 1;
    
    while( --argc )
    {
        ++argv;
        if( strcmp(*argv,"-exe")==0 || strcmp(*argv,"--exe")==0 ||
            strcmp(*argv,"-dso")==0 || strcmp(*argv,"--dso")==0 ||
            strcmp(*argv,"-dylib")==0 || strcmp(*argv,"--dylib")==0 ||
            strcmp(*argv,"--verify")==0 )
        {
            if(strcmp(*argv,"--verify")==0)
                addFingerprint=0;

            if( argc > 0 )
            {
                filename = *++argv;
                argc--;
            }
        }
        else if(strcmp(*argv,"-d")==0 || strcmp(*argv,"-debug")==0 || strcmp(*argv,"--debug")==0)
        {
            if( gVerbosity < 2 )
                gVerbosity = 2;
            else
                gVerbosity++;
        }
        else if(strcmp(*argv,"-q")==0 || strcmp(*argv,"-quiet")==0 || strcmp(*argv,"--quiet")==0)
            gVerbosity = 0;
        else if(strncmp(*argv,"-",1)!=0) {
            filename = *argv;
        }
    }
    
    if( !filename )
    {
        print_usage(pname);
        return 1;
    }

    if( access(filename, R_OK) )
    {
        fprintf(stderr, "Can't access %s\n", filename);
        return 1;
    }

    return make_fingerprint( filename, addFingerprint );
}

