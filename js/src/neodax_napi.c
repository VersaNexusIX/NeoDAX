/* Portable feature-test macros — must come before ALL system headers */
#if defined(__APPLE__)
#  define _DARWIN_C_SOURCE 1
#elif !defined(_GNU_SOURCE)
#  define _GNU_SOURCE 1
#  define _POSIX_C_SOURCE 200809L
#endif

#include <node_api.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include "dax.h"
#include "x86.h"
#include "arm64.h"
#include "riscv.h"

#define NAPI_CALL(env, call)                                      \
    do {                                                          \
        napi_status _s = (call);                                  \
        if (_s != napi_ok) {                                      \
            const napi_extended_error_info *ei = NULL;            \
            napi_get_last_error_info((env), &ei);                 \
            napi_throw_error((env), NULL,                         \
                ei && ei->error_message ? ei->error_message       \
                                        : "napi call failed");    \
            return NULL;                                          \
        }                                                         \
    } while(0)

static void set_str(napi_env e, napi_value o, const char *k, const char *v) {
    napi_value s; napi_create_string_utf8(e, v?v:"", NAPI_AUTO_LENGTH, &s);
    napi_set_named_property(e, o, k, s);
}
static void set_u32(napi_env e, napi_value o, const char *k, uint32_t v) {
    napi_value n; napi_create_uint32(e, v, &n); napi_set_named_property(e, o, k, n);
}
static void set_i32(napi_env e, napi_value o, const char *k, int32_t v) {
    napi_value n; napi_create_int32(e, v, &n); napi_set_named_property(e, o, k, n);
}
static void set_dbl(napi_env e, napi_value o, const char *k, double v) {
    napi_value n; napi_create_double(e, v, &n); napi_set_named_property(e, o, k, n);
}
static void set_u64(napi_env e, napi_value o, const char *k, uint64_t v) {
    napi_value n; napi_create_bigint_uint64(e, v, &n); napi_set_named_property(e, o, k, n);
}
static void set_bool(napi_env e, napi_value o, const char *k, int v) {
    napi_value b; napi_get_boolean(e, v!=0, &b); napi_set_named_property(e, o, k, b);
}
static void set_null(napi_env e, napi_value o, const char *k) {
    napi_value n; napi_get_null(e, &n); napi_set_named_property(e, o, k, n);
}

static uint64_t get_u64_arg(napi_env env, napi_value v) {
    napi_valuetype vt;
    napi_typeof(env, v, &vt);
    if (vt == napi_bigint) {
        uint64_t out = 0; bool lossless;
        napi_get_value_bigint_uint64(env, v, &out, &lossless);
        return out;
    }
    double d = 0; napi_get_value_double(env, v, &d);
    return (uint64_t)d;
}

static char *get_str_arg(napi_env env, napi_value v, char *buf, size_t bufsz) {
    size_t sz; napi_get_value_string_utf8(env, v, buf, bufsz, &sz);
    return buf;
}

static napi_value build_section(napi_env env, dax_section_t *s) {
    napi_value o; napi_create_object(env, &o);
    set_str(env, o, "name",       s->name);
    set_u64(env, o, "vaddr",      s->vaddr);
    set_u64(env, o, "offset",     s->offset);
    set_u64(env, o, "size",       s->size);
    set_u32(env, o, "flags",      s->flags);
    set_u32(env, o, "insnCount",  s->insn_count);
    const char *t="other";
    switch(s->type){
        case SEC_TYPE_CODE:    t="code";    break;
        case SEC_TYPE_DATA:    t="data";    break;
        case SEC_TYPE_RODATA:  t="rodata";  break;
        case SEC_TYPE_BSS:     t="bss";     break;
        case SEC_TYPE_PLT:     t="plt";     break;
        case SEC_TYPE_GOT:     t="got";     break;
        case SEC_TYPE_DYNAMIC: t="dynamic"; break;
        case SEC_TYPE_DEBUG:   t="debug";   break;
        default: break;
    }
    set_str(env, o, "type", t);
    set_bool(env, o, "isExecutable", (s->flags & 0x4) || (s->flags & 0x20000000));
    set_bool(env, o, "isWritable",   (s->flags & 0x2) != 0);
    set_bool(env, o, "isReadable",   (s->flags & 0x1) != 0);
    return o;
}

static napi_value build_symbol(napi_env env, dax_symbol_t *s) {
    napi_value o; napi_create_object(env, &o);
    set_str(env, o, "name",      s->name);
    set_str(env, o, "demangled", s->demangled[0] ? s->demangled : s->name);
    set_u64(env, o, "address",   s->address);
    set_u64(env, o, "size",      s->size);
    set_bool(env, o, "isEntry",  s->is_entry);
    const char *t="unknown";
    switch(s->type){
        case SYM_FUNC:   t="function"; break;
        case SYM_OBJECT: t="object";   break;
        case SYM_IMPORT: t="import";   break;
        case SYM_EXPORT: t="export";   break;
        case SYM_WEAK:   t="weak";     break;
        case SYM_LOCAL:  t="local";    break;
        default: break;
    }
    set_str(env, o, "type", t);
    return o;
}

static napi_value build_function(napi_env env, dax_func_t *f) {
    napi_value o; napi_create_object(env, &o);
    /* end=0 means the function boundary is unknown (no ret found); use start as fallback */
    uint64_t fn_end  = (f->end > 0) ? f->end : f->start;
    uint64_t fn_size = (fn_end > f->start) ? fn_end - f->start : 0;
    set_str(env, o, "name",       f->name);
    set_u64(env, o, "start",      f->start);
    set_u64(env, o, "end",        fn_end);
    set_u64(env, o, "size",       fn_size);
    set_u32(env, o, "insnCount",  f->insn_count);
    set_u32(env, o, "blockCount", f->block_count);
    set_bool(env, o, "hasLoops",  f->has_loops);
    set_bool(env, o, "hasCalls",  f->has_calls);
    set_i32(env, o, "symIndex",   f->sym_idx);
    return o;
}

static napi_value build_xref(napi_env env, dax_xref_t *x) {
    napi_value o; napi_create_object(env, &o);
    set_u64(env, o, "from",   x->from);
    set_u64(env, o, "to",     x->to);
    set_bool(env, o, "isCall", x->is_call);
    return o;
}

static napi_value build_ustring(napi_env env, dax_ustring_t *u) {
    napi_value o; napi_create_object(env, &o);
    set_u64(env, o, "address",    u->address);
    set_str(env, o, "value",      u->value_utf8);
    set_u32(env, o, "byteLength", u->byte_length);
    const char *enc="ascii";
    switch(u->encoding){
        case STR_ENC_UTF8:    enc="utf-8";    break;
        case STR_ENC_UTF16LE: enc="utf-16le"; break;
        case STR_ENC_UTF16BE: enc="utf-16be"; break;
        default: break;
    }
    set_str(env, o, "encoding", enc);
    return o;
}

static napi_value build_block(napi_env env, dax_block_t *b) {
    napi_value o; napi_create_object(env, &o);
    set_u64(env, o, "start",    b->start);
    set_u64(env, o, "end",      b->end);
    set_i32(env, o, "id",       b->id);
    set_i32(env, o, "funcIdx",  b->func_idx);
    set_bool(env, o, "isEntry", b->is_entry);
    set_bool(env, o, "isExit",  b->is_exit);
    set_i32(env, o, "nsucc",    b->nsucc);
    set_i32(env, o, "npred",    b->npred);
    return o;
}

static napi_value build_info(napi_env env, dax_binary_t *bin) {
    napi_value o; napi_create_object(env, &o);
    set_str(env, o, "file",        bin->filepath);
    set_str(env, o, "format",      dax_fmt_str(bin->fmt));
    set_str(env, o, "arch",        dax_arch_str(bin->arch));
    set_str(env, o, "os",          dax_os_str(bin->os));
    set_u64(env, o, "entry",       bin->entry);
    set_u64(env, o, "base",        bin->base);
    set_u64(env, o, "imageSize",   bin->image_size);
    set_u64(env, o, "codeSize",    bin->code_size);
    set_u64(env, o, "dataSize",    bin->data_size);
    set_u32(env, o, "totalInsns",  bin->total_insns);
    set_u32(env, o, "nsections",   (uint32_t)bin->nsections);
    set_u32(env, o, "nsymbols",    (uint32_t)bin->nsymbols);
    set_u32(env, o, "nfunctions",  (uint32_t)bin->nfunctions);
    set_u32(env, o, "nxrefs",      (uint32_t)bin->nxrefs);
    set_u32(env, o, "nblocks",     (uint32_t)bin->nblocks);
    set_u32(env, o, "ncomments",   (uint32_t)bin->ncomments);
    set_u32(env, o, "nustrings",   (uint32_t)bin->nustrings);
    set_bool(env, o, "isPie",      bin->is_pie);
    set_bool(env, o, "isStripped", bin->is_stripped);
    set_bool(env, o, "hasDebug",   bin->has_debug);
    set_str(env, o, "sha256",      bin->sha256);
    set_str(env, o, "buildId",     bin->build_id);
    set_str(env, o, "version",     DAX_VERSION);
    return o;
}

static dax_binary_t *get_handle(napi_env env, napi_value obj) {
    napi_value h; napi_get_named_property(env, obj, "_handle", &h);
    void *p = NULL; napi_get_value_external(env, h, &p);
    return (dax_binary_t *)p;
}

static void ensure_symbols(dax_binary_t *bin) {
    if (!bin->symbols) dax_sym_load(bin);
}

static void ensure_functions(dax_binary_t *bin) {
    ensure_symbols(bin);
    if (!bin->functions) {
        for (int si = 0; si < bin->nsections; si++) {
            dax_section_t *sec = &bin->sections[si];
            if (sec->type == SEC_TYPE_CODE && sec->size > 0 &&
                sec->offset + sec->size <= bin->size)
                dax_func_detect(bin, bin->data+sec->offset, (size_t)sec->size, sec->vaddr, sec);
        }
    }
}

static void ensure_xrefs(dax_binary_t *bin) {
    ensure_symbols(bin);
    if (!bin->xrefs) dax_xref_build(bin);
}

static void ensure_cfg(dax_binary_t *bin) {
    ensure_functions(bin);
    if (bin->nblocks == 0 && bin->nfunctions > 0) {
        for (int fi = 0; fi < bin->nfunctions; fi++) {
            dax_func_t *fn = &bin->functions[fi];
            for (int si = 0; si < bin->nsections; si++) {
                dax_section_t *sec = &bin->sections[si];
                if (fn->start >= sec->vaddr && fn->start < sec->vaddr+sec->size &&
                    sec->offset+sec->size <= bin->size) {
                    dax_cfg_build(bin, bin->data+sec->offset, (size_t)sec->size, sec->vaddr, fi);
                    break;
                }
            }
        }
    }
}

static napi_value ndx_load(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    if (argc < 1) { napi_throw_type_error(env, NULL, "load(path)"); return NULL; }

    char path[1024] = {0};
    get_str_arg(env, args[0], path, sizeof(path));

    dax_binary_t *bin = (dax_binary_t *)calloc(1, sizeof(dax_binary_t));
    if (!bin) { napi_throw_error(env, NULL, "OOM"); return NULL; }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    if (dax_load_binary(path, bin) != 0) {
        free(bin);
        napi_throw_error(env, NULL, "Failed to load binary — check path and permissions");
        return NULL;
    }

    dax_compute_sha256(bin);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (t1.tv_sec-t0.tv_sec)*1000.0 + (t1.tv_nsec-t0.tv_nsec)/1e6;

    napi_value ext; napi_create_external(env, bin, NULL, NULL, &ext);
    napi_value result; napi_create_object(env, &result);
    napi_set_named_property(env, result, "info",     build_info(env, bin));
    napi_set_named_property(env, result, "_handle",  ext);
    set_dbl(env, result, "loadTimeMs", ms);
    return result;
}

static napi_value ndx_close(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    if (argc < 1) { napi_throw_type_error(env, NULL, "close(handle)"); return NULL; }
    void *p = NULL; napi_get_value_external(env, args[0], &p);
    if (p) { dax_free_binary((dax_binary_t *)p); free(p); }
    napi_value u; napi_get_undefined(env, &u); return u;
}

static napi_value ndx_sections(napi_env env, napi_callback_info info) {
    size_t argc=1; napi_value args[1]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin) { napi_throw_error(env,NULL,"Invalid handle"); return NULL; }
    napi_value arr; napi_create_array_with_length(env,(size_t)bin->nsections,&arr);
    for (int i=0;i<bin->nsections;i++) napi_set_element(env,arr,(uint32_t)i,build_section(env,&bin->sections[i]));
    return arr;
}

static napi_value ndx_symbols(napi_env env, napi_callback_info info) {
    size_t argc=1; napi_value args[1]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin) { napi_throw_error(env,NULL,"Invalid handle"); return NULL; }
    ensure_symbols(bin);
    napi_value arr; napi_create_array_with_length(env,(size_t)bin->nsymbols,&arr);
    for (int i=0;i<bin->nsymbols;i++) napi_set_element(env,arr,(uint32_t)i,build_symbol(env,&bin->symbols[i]));
    return arr;
}

static napi_value ndx_functions(napi_env env, napi_callback_info info) {
    size_t argc=1; napi_value args[1]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin) { napi_throw_error(env,NULL,"Invalid handle"); return NULL; }
    ensure_functions(bin);
    napi_value arr; napi_create_array_with_length(env,(size_t)bin->nfunctions,&arr);
    for (int i=0;i<bin->nfunctions;i++) napi_set_element(env,arr,(uint32_t)i,build_function(env,&bin->functions[i]));
    return arr;
}

static napi_value ndx_xrefs(napi_env env, napi_callback_info info) {
    size_t argc=1; napi_value args[1]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin) { napi_throw_error(env,NULL,"Invalid handle"); return NULL; }
    ensure_xrefs(bin);
    napi_value arr; napi_create_array_with_length(env,(size_t)bin->nxrefs,&arr);
    for (int i=0;i<bin->nxrefs;i++) napi_set_element(env,arr,(uint32_t)i,build_xref(env,&bin->xrefs[i]));
    return arr;
}

static napi_value ndx_unicode(napi_env env, napi_callback_info info) {
    size_t argc=1; napi_value args[1]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin) { napi_throw_error(env,NULL,"Invalid handle"); return NULL; }
    if (!bin->ustrings) dax_scan_unicode(bin);
    napi_value arr; napi_create_array_with_length(env,(size_t)bin->nustrings,&arr);
    for (int i=0;i<bin->nustrings;i++) napi_set_element(env,arr,(uint32_t)i,build_ustring(env,&bin->ustrings[i]));
    return arr;
}

static napi_value ndx_blocks(napi_env env, napi_callback_info info) {
    size_t argc=1; napi_value args[1]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin) { napi_throw_error(env,NULL,"Invalid handle"); return NULL; }
    ensure_cfg(bin);
    napi_value arr; napi_create_array_with_length(env,(size_t)bin->nblocks,&arr);
    for (int i=0;i<bin->nblocks;i++) napi_set_element(env,arr,(uint32_t)i,build_block(env,&bin->blocks[i]));
    return arr;
}

static napi_value ndx_disasm(napi_env env, napi_callback_info info) {
    size_t argc=2; napi_value args[2]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin) { napi_throw_error(env,NULL,"Invalid handle"); return NULL; }
    char section[64] = ".text";
    if (argc>=2) { napi_valuetype vt; napi_typeof(env,args[1],&vt); if(vt==napi_string) get_str_arg(env,args[1],section,sizeof(section)); }
    dax_opts_t opts; memset(&opts,0,sizeof(opts));
    opts.show_addr=1; opts.color=0; opts.symbols=1; opts.strings=1;
    opts.start_addr=0; opts.end_addr=(uint64_t)-1;
    strncpy(opts.section,section,sizeof(opts.section)-1);
    ensure_symbols(bin);
    char *buf=NULL; size_t bsz=0;
    FILE *stream = open_memstream(&buf,&bsz);
    if (!stream) { napi_throw_error(env,NULL,"open_memstream failed"); return NULL; }
    if      (bin->arch==ARCH_X86_64)  dax_disasm_x86_64(bin,&opts,stream);
    else if (bin->arch==ARCH_ARM64)   dax_disasm_arm64(bin,&opts,stream);
    else if (bin->arch==ARCH_RISCV64) dax_disasm_riscv64(bin,&opts,stream);
    fclose(stream);
    napi_value r; napi_create_string_utf8(env,buf?buf:"",bsz,&r);
    if (buf) free(buf);
    return r;
}

static napi_value ndx_disasm_json(napi_env env, napi_callback_info info) {
    size_t argc=3; napi_value args[3]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin) { napi_throw_error(env,NULL,"Invalid handle"); return NULL; }

    char section[64] = ".text";
    uint32_t limit = 5000;
    uint32_t offset_n = 0;

    if (argc>=2) { napi_valuetype vt; napi_typeof(env,args[1],&vt); if(vt==napi_string) get_str_arg(env,args[1],section,sizeof(section)); }
    if (argc>=3) {
        napi_valuetype vt; napi_typeof(env,args[2],&vt);
        if (vt==napi_object) {
            napi_value v;
            if (napi_get_named_property(env,args[2],"limit",&v)==napi_ok) { napi_valuetype vt2; napi_typeof(env,v,&vt2); if(vt2==napi_number){double d;napi_get_value_double(env,v,&d);limit=(uint32_t)d;}}
            if (napi_get_named_property(env,args[2],"offset",&v)==napi_ok){ napi_valuetype vt2; napi_typeof(env,v,&vt2); if(vt2==napi_number){double d;napi_get_value_double(env,v,&d);offset_n=(uint32_t)d;}}
        }
    }

    dax_section_t *sec = NULL;
    for (int i=0;i<bin->nsections;i++) if(!strcmp(bin->sections[i].name,section)){sec=&bin->sections[i];break;}
    if (!sec||sec->offset+sec->size>bin->size) { napi_value a; napi_create_array_with_length(env,0,&a); return a; }

    ensure_symbols(bin);

    uint8_t *code = bin->data+sec->offset;
    size_t   sz   = (size_t)sec->size;
    uint64_t base = sec->vaddr;
    size_t   off  = 0;
    uint32_t idx  = 0;
    uint32_t count= 0;

    napi_value arr; napi_create_array_with_length(env,0,&arr);

    if (bin->arch==ARCH_X86_64) {
        while (off < sz) {
            x86_insn_t insn;
            memset(&insn,0,sizeof(insn));
            int len = x86_decode(code+off,sz-off,base+off,&insn);
            if (len<=0){off++;continue;}
            if (idx >= offset_n && count < limit) {
                napi_value o; napi_create_object(env,&o);
                set_u64(env,o,"address",insn.address);
                set_str(env,o,"mnemonic",insn.mnemonic);
                set_str(env,o,"operands",insn.ops);
                set_u32(env,o,"size",(uint32_t)insn.length);
                uint8_t ilen = insn.length > 15 ? 15 : insn.length;
                napi_value ba; napi_create_array_with_length(env,(size_t)ilen,&ba);
                for (int b=0;b<(int)ilen;b++){napi_value bv;napi_create_uint32(env,code[off+b],&bv);napi_set_element(env,ba,(uint32_t)b,bv);}
                napi_set_named_property(env,o,"bytes",ba);
                dax_symbol_t *sym = dax_sym_find(bin,insn.address);
                if (sym) set_str(env,o,"symbol",sym->demangled[0]?sym->demangled:sym->name);
                else     set_null(env,o,"symbol");
                const char *grp = dax_igrp_str(dax_classify_x86(insn.mnemonic));
                set_str(env,o,"group",grp&&grp[0]?grp:"unknown");
                napi_set_element(env,arr,count,o);
                count++;
            }
            idx++;
            off+=(size_t)insn.length;
        }
    } else if (bin->arch==ARCH_ARM64) {
        while (off+4<=sz) {
            uint32_t raw=(uint32_t)(code[off])|(code[off+1]<<8)|(code[off+2]<<16)|(code[off+3]<<24);
            a64_insn_t insn; memset(&insn,0,sizeof(insn)); a64_decode(raw,base+off,&insn);
            if (idx>=offset_n && count<limit) {
                napi_value o; napi_create_object(env,&o);
                set_u64(env,o,"address",base+off);
                set_str(env,o,"mnemonic",insn.mnemonic);
                set_str(env,o,"operands",insn.operands);
                set_u32(env,o,"size",4);
                napi_value ba; napi_create_array_with_length(env,4,&ba);
                for(int b=0;b<4;b++){napi_value bv;napi_create_uint32(env,code[off+b],&bv);napi_set_element(env,ba,(uint32_t)b,bv);}
                napi_set_named_property(env,o,"bytes",ba);
                dax_symbol_t *sym=dax_sym_find(bin,base+off);
                if(sym) set_str(env,o,"symbol",sym->demangled[0]?sym->demangled:sym->name);
                else    set_null(env,o,"symbol");
                const char *grp=dax_igrp_str(dax_classify_arm64(insn.mnemonic));
                set_str(env,o,"group",grp&&grp[0]?grp:"unknown");
                napi_set_element(env,arr,count,o); count++;
            }
            idx++; off+=4;
        }
    } else if (bin->arch==ARCH_RISCV64) {
        /* RISC-V RV64GC — instructions are 2 (compressed) or 4 bytes */
        while (off < sz) {
            rv_insn_t insn;
            memset(&insn,0,sizeof(insn));
            int rlen = rv_decode(code+off, sz-off, base+off, &insn);
            if (rlen<=0){off++;continue;}
            if (idx>=offset_n && count<limit) {
                napi_value o; napi_create_object(env,&o);
                set_u64(env,o,"address",insn.address);
                set_str(env,o,"mnemonic",insn.mnemonic);
                set_str(env,o,"operands",insn.operands);
                set_u32(env,o,"size",(uint32_t)rlen);
                uint8_t blen=(uint8_t)(rlen>4?4:rlen);
                napi_value ba; napi_create_array_with_length(env,(size_t)blen,&ba);
                for(int b=0;b<(int)blen;b++){napi_value bv;napi_create_uint32(env,code[off+b],&bv);napi_set_element(env,ba,(uint32_t)b,bv);}
                napi_set_named_property(env,o,"bytes",ba);
                dax_symbol_t *sym=dax_sym_find(bin,insn.address);
                if(sym) set_str(env,o,"symbol",sym->demangled[0]?sym->demangled:sym->name);
                else    set_null(env,o,"symbol");
                const char *grp=dax_igrp_str(dax_classify_riscv(insn.mnemonic));
                set_str(env,o,"group",grp&&grp[0]?grp:"unknown");
                napi_set_element(env,arr,count,o); count++;
            }
            idx++; off+=(size_t)rlen;
        }
    }
    return arr;
}

static napi_value ndx_analyze(napi_env env, napi_callback_info info) {
    size_t argc=1; napi_value args[1]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin) { napi_throw_error(env,NULL,"Invalid handle"); return NULL; }

    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);

    ensure_symbols(bin);
    ensure_xrefs(bin);
    ensure_functions(bin);
    ensure_cfg(bin);
    if (!bin->ustrings) dax_scan_unicode(bin);

    clock_gettime(CLOCK_MONOTONIC,&t1);
    double ms=(t1.tv_sec-t0.tv_sec)*1000.0+(t1.tv_nsec-t0.tv_nsec)/1e6;

    napi_value result; napi_create_object(env,&result);

    napi_value sym_arr; napi_create_array_with_length(env,(size_t)bin->nsymbols,&sym_arr);
    for(int i=0;i<bin->nsymbols;i++) napi_set_element(env,sym_arr,(uint32_t)i,build_symbol(env,&bin->symbols[i]));
    napi_set_named_property(env,result,"symbols",sym_arr);

    napi_value fn_arr; napi_create_array_with_length(env,(size_t)bin->nfunctions,&fn_arr);
    for(int i=0;i<bin->nfunctions;i++) napi_set_element(env,fn_arr,(uint32_t)i,build_function(env,&bin->functions[i]));
    napi_set_named_property(env,result,"functions",fn_arr);

    napi_value xr_arr; napi_create_array_with_length(env,(size_t)bin->nxrefs,&xr_arr);
    for(int i=0;i<bin->nxrefs;i++) napi_set_element(env,xr_arr,(uint32_t)i,build_xref(env,&bin->xrefs[i]));
    napi_set_named_property(env,result,"xrefs",xr_arr);

    napi_value bl_arr; napi_create_array_with_length(env,(size_t)bin->nblocks,&bl_arr);
    for(int i=0;i<bin->nblocks;i++) napi_set_element(env,bl_arr,(uint32_t)i,build_block(env,&bin->blocks[i]));
    napi_set_named_property(env,result,"blocks",bl_arr);

    napi_value us_arr; napi_create_array_with_length(env,(size_t)bin->nustrings,&us_arr);
    for(int i=0;i<bin->nustrings;i++) napi_set_element(env,us_arr,(uint32_t)i,build_ustring(env,&bin->ustrings[i]));
    napi_set_named_property(env,result,"unicodeStrings",us_arr);

    napi_set_named_property(env,result,"info",build_info(env,bin));
    set_dbl(env,result,"analysisTimeMs",ms);
    return result;
}

static napi_value ndx_sym_at(napi_env env, napi_callback_info info) {
    size_t argc=2; napi_value args[2]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin||argc<2) { napi_throw_error(env,NULL,"sym_at(handle,address)"); return NULL; }
    ensure_symbols(bin);
    uint64_t addr=get_u64_arg(env,args[1]);
    dax_symbol_t *sym=dax_sym_find(bin,addr);
    if (!sym){napi_value n;napi_get_null(env,&n);return n;}
    return build_symbol(env,sym);
}

static napi_value ndx_func_at(napi_env env, napi_callback_info info) {
    size_t argc=2; napi_value args[2]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin||argc<2) { napi_throw_error(env,NULL,"func_at(handle,address)"); return NULL; }
    ensure_functions(bin);
    uint64_t addr=get_u64_arg(env,args[1]);
    dax_func_t *fn=dax_func_find(bin,addr);
    if (!fn){napi_value n;napi_get_null(env,&n);return n;}
    return build_function(env,fn);
}

static napi_value ndx_xrefs_to(napi_env env, napi_callback_info info) {
    size_t argc=2; napi_value args[2]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin||argc<2) { napi_throw_error(env,NULL,"xrefs_to(handle,address)"); return NULL; }
    ensure_xrefs(bin);
    uint64_t addr=get_u64_arg(env,args[1]);
    dax_xref_t out[64]; int n=dax_xref_find_to(bin,addr,out,64);
    napi_value arr; napi_create_array_with_length(env,(size_t)n,&arr);
    for(int i=0;i<n;i++) napi_set_element(env,arr,(uint32_t)i,build_xref(env,&out[i]));
    return arr;
}

static napi_value ndx_xrefs_from(napi_env env, napi_callback_info info) {
    size_t argc=2; napi_value args[2]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin||argc<2) { napi_throw_error(env,NULL,"xrefs_from(handle,address)"); return NULL; }
    ensure_xrefs(bin);
    uint64_t addr=get_u64_arg(env,args[1]);
    napi_value arr; napi_create_array_with_length(env,0,&arr);
    uint32_t count=0;
    for(int i=0;i<bin->nxrefs && count<256;i++)
        if(bin->xrefs[i].from==addr){napi_set_element(env,arr,count++,build_xref(env,&bin->xrefs[i]));}
    return arr;
}

static napi_value ndx_section_by_name(napi_env env, napi_callback_info info) {
    size_t argc=2; napi_value args[2]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin||argc<2) { napi_throw_error(env,NULL,"section_by_name(handle,name)"); return NULL; }
    char name[64]={0}; get_str_arg(env,args[1],name,sizeof(name));
    for(int i=0;i<bin->nsections;i++)
        if(!strcmp(bin->sections[i].name,name)) return build_section(env,&bin->sections[i]);
    napi_value n; napi_get_null(env,&n); return n;
}

static napi_value ndx_section_at(napi_env env, napi_callback_info info) {
    size_t argc=2; napi_value args[2]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin||argc<2) { napi_throw_error(env,NULL,"section_at(handle,address)"); return NULL; }
    uint64_t addr=get_u64_arg(env,args[1]);
    for(int i=0;i<bin->nsections;i++){
        dax_section_t *s=&bin->sections[i];
        if(addr>=s->vaddr && addr<s->vaddr+s->size) return build_section(env,s);
    }
    napi_value n; napi_get_null(env,&n); return n;
}

static napi_value ndx_read_bytes(napi_env env, napi_callback_info info) {
    size_t argc=3; napi_value args[3]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin||argc<3) { napi_throw_error(env,NULL,"read_bytes(handle,address,length)"); return NULL; }
    uint64_t addr=get_u64_arg(env,args[1]);
    double dlen=0; napi_get_value_double(env,args[2],&dlen);
    size_t rlen=(size_t)dlen;
    if (rlen==0||rlen>65536){napi_value n;napi_get_null(env,&n);return n;}
    for(int i=0;i<bin->nsections;i++){
        dax_section_t *s=&bin->sections[i];
        if(addr<s->vaddr||addr>=s->vaddr+s->size) continue;
        uint64_t off=s->offset+(addr-s->vaddr);
        if(off>=bin->size) continue;
        if(off+rlen>bin->size) rlen=(size_t)(bin->size-off);
        napi_value buf; void *bdata;
        napi_create_arraybuffer(env,rlen,&bdata,&buf);
        memcpy(bdata,bin->data+off,rlen);
        napi_value view; napi_create_typedarray(env,napi_uint8_array,rlen,buf,0,&view);
        return view;
    }
    /* Fallback: if entry is past a known section (common in Mach-O),
       try to find its file offset via the first executable section's base */
    if(bin->nsections>0 && bin->base>0 && addr>=bin->base){
        for(int i=0;i<bin->nsections;i++){
            dax_section_t *s=&bin->sections[i];
            if(s->type!=SEC_TYPE_CODE||s->offset==0) continue;
            /* estimate file offset assuming vaddr-base == fileoff-section_start */
            uint64_t vdiff = addr - s->vaddr;
            if(vdiff < s->size){
                uint64_t off = s->offset + vdiff;
                if(off+rlen>bin->size) rlen=(size_t)(bin->size-off);
                napi_value buf; void *bdata;
                napi_create_arraybuffer(env,rlen,&bdata,&buf);
                memcpy(bdata,bin->data+off,rlen);
                napi_value view; napi_create_typedarray(env,napi_uint8_array,rlen,buf,0,&view);
                return view;
            }
        }
    }
    napi_value n; napi_get_null(env,&n); return n;
}

static napi_value ndx_hottest_functions(napi_env env, napi_callback_info info) {
    size_t argc=2; napi_value args[2]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin) { napi_throw_error(env,NULL,"Invalid handle"); return NULL; }
    uint32_t topn=20;
    if (argc>=2){double d;napi_get_value_double(env,args[1],&d);topn=(uint32_t)d;}
    ensure_functions(bin); ensure_xrefs(bin);

    typedef struct { int fi; int calls; } hot_t;
    hot_t *hot=(hot_t*)calloc((size_t)bin->nfunctions,sizeof(hot_t));
    if (!hot){napi_value n;napi_get_null(env,&n);return n;}
    for(int i=0;i<bin->nfunctions;i++) hot[i].fi=i;
    for(int x=0;x<bin->nxrefs;x++){
        if(!bin->xrefs[x].is_call) continue;
        uint64_t to=bin->xrefs[x].to;
        for(int i=0;i<bin->nfunctions;i++)
            if(bin->functions[i].start==to){hot[i].calls++;break;}
    }
    for(int i=0;i<bin->nfunctions-1;i++)
        for(int j=i+1;j<bin->nfunctions;j++)
            if(hot[j].calls>hot[i].calls){hot_t tmp=hot[i];hot[i]=hot[j];hot[j]=tmp;}

    if (topn>(uint32_t)bin->nfunctions) topn=(uint32_t)bin->nfunctions;
    napi_value arr; napi_create_array_with_length(env,(size_t)topn,&arr);
    for(uint32_t i=0;i<topn;i++){
        napi_value o; napi_create_object(env,&o);
        napi_value fn=build_function(env,&bin->functions[hot[i].fi]);
        napi_set_named_property(env,o,"function",fn);
        set_i32(env,o,"callCount",hot[i].calls);
        napi_set_element(env,arr,i,o);
    }
    free(hot);
    return arr;
}

static napi_value ndx_strings(napi_env env, napi_callback_info info) {
    size_t argc=1; napi_value args[1]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin) { napi_throw_error(env,NULL,"Invalid handle"); return NULL; }

    napi_value arr; napi_create_array_with_length(env,0,&arr);
    uint32_t count=0;
    for(int si=0;si<bin->nsections;si++){
        dax_section_t *sec=&bin->sections[si];
        if(sec->type==SEC_TYPE_CODE) continue;
        if(sec->offset+sec->size>bin->size) continue;
        uint8_t *p=(uint8_t*)bin->data+sec->offset;
        size_t slen=(size_t)sec->size;
        for(size_t i=0;i<slen&&count<8192;){
            if(!isprint(p[i])){i++;continue;}
            size_t j=i;
            while(j<slen&&j-i<1024&&isprint(p[j])){j++;}
            if(j-i>=4&&(j>=slen||p[j]==0)){
                napi_value o; napi_create_object(env,&o);
                set_u64(env,o,"address",sec->vaddr+i);
                char tmp[1024+1]; size_t l=j-i<1024?j-i:1024; memcpy(tmp,p+i,l); tmp[l]=0;
                set_str(env,o,"value",tmp);
                set_u32(env,o,"length",(uint32_t)l);
                napi_set_element(env,arr,count++,o);
            }
            i=j+1;
        }
    }
    return arr;
}

static napi_value ndx_version(napi_env env, napi_callback_info info) {
    (void)info; napi_value v; napi_create_string_utf8(env,DAX_VERSION,NAPI_AUTO_LENGTH,&v); return v;
}

static napi_value ndx_info(napi_env env, napi_callback_info info) {
    size_t argc=1; napi_value args[1]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin = get_handle(env, args[0]);
    if (!bin) { napi_throw_error(env,NULL,"Invalid handle"); return NULL; }
    return build_info(env,bin);
}


static napi_value ndx_symexec(napi_env env, napi_callback_info info) {
    size_t argc=2; napi_value args[2]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin=get_handle(env,args[0]);
    if(!bin){napi_throw_error(env,NULL,"Invalid handle");return NULL;}
    int func_idx=-1;
    if(argc>=2){double d;napi_get_value_double(env,args[1],&d);func_idx=(int)d;}
    char *buf=NULL; size_t bsz=0;
    FILE *stream=open_memstream(&buf,&bsz);
    if(!stream){napi_throw_error(env,NULL,"open_memstream failed");return NULL;}
    dax_opts_t opts; memset(&opts,0,sizeof(opts)); opts.color=0;
    if(func_idx>=0) dax_symexec_func(bin,func_idx,&opts,stream);
    else            dax_symexec_all(bin,&opts,stream);
    fclose(stream);
    napi_value r; napi_create_string_utf8(env,buf?buf:"",bsz,&r);
    if(buf) { free(buf); }
    return r;
}

static napi_value ndx_ssa(napi_env env, napi_callback_info info) {
    size_t argc=2; napi_value args[2]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin=get_handle(env,args[0]);
    if(!bin){napi_throw_error(env,NULL,"Invalid handle");return NULL;}
    int func_idx=-1;
    if(argc>=2){double d;napi_get_value_double(env,args[1],&d);func_idx=(int)d;}
    ensure_functions(bin);
    char *buf=NULL; size_t bsz=0;
    FILE *stream=open_memstream(&buf,&bsz);
    if(!stream){napi_throw_error(env,NULL,"open_memstream failed");return NULL;}
    dax_opts_t opts; memset(&opts,0,sizeof(opts)); opts.color=0;
    if(func_idx>=0) dax_ssa_lift_func(bin,func_idx,&opts,stream);
    else            dax_ssa_lift_all(bin,&opts,stream);
    fclose(stream);
    napi_value r; napi_create_string_utf8(env,buf?buf:"",bsz,&r);
    if(buf) { free(buf); }
    return r;
}

static napi_value ndx_decompile(napi_env env, napi_callback_info info) {
    size_t argc=2; napi_value args[2]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin=get_handle(env,args[0]);
    if(!bin){napi_throw_error(env,NULL,"Invalid handle");return NULL;}
    int func_idx=-1;
    if(argc>=2){double d;napi_get_value_double(env,args[1],&d);func_idx=(int)d;}
    ensure_functions(bin);
    char *buf=NULL; size_t bsz=0;
    FILE *stream=open_memstream(&buf,&bsz);
    if(!stream){napi_throw_error(env,NULL,"open_memstream failed");return NULL;}
    dax_opts_t opts; memset(&opts,0,sizeof(opts)); opts.color=0;
    if(func_idx>=0) dax_decompile_func(bin,func_idx,&opts,stream);
    else            dax_decompile_all(bin,&opts,stream);
    fclose(stream);
    napi_value r; napi_create_string_utf8(env,buf?buf:"",bsz,&r);
    if(buf) { free(buf); }
    return r;
}

static napi_value ndx_emulate(napi_env env, napi_callback_info info) {
    size_t argc=3; napi_value args[3]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin=get_handle(env,args[0]);
    if(!bin){napi_throw_error(env,NULL,"Invalid handle");return NULL;}
    int func_idx=0;
    if(argc>=2){double d;napi_get_value_double(env,args[1],&d);func_idx=(int)d;}
    uint64_t init_regs[8]={0};
    if(argc>=3){
        napi_valuetype vt; napi_typeof(env,args[2],&vt);
        if(vt==napi_object){
            for(int i=0;i<8;i++){
                char key[4]; snprintf(key,4,"%d",i);
                napi_value v;
                if(napi_get_named_property(env,args[2],key,&v)==napi_ok){
                    napi_valuetype vt2; napi_typeof(env,v,&vt2);
                    if(vt2==napi_bigint) napi_get_value_bigint_uint64(env,v,&init_regs[i],NULL);
                    else if(vt2==napi_number){double dd;napi_get_value_double(env,v,&dd);init_regs[i]=(uint64_t)dd;}
                }
            }
        }
    }
    ensure_functions(bin);
    char *buf=NULL; size_t bsz=0;
    FILE *stream=open_memstream(&buf,&bsz);
    if(!stream){napi_throw_error(env,NULL,"open_memstream failed");return NULL;}
    dax_opts_t opts; memset(&opts,0,sizeof(opts)); opts.color=0;
    dax_emulate_func(bin,func_idx,init_regs,8,&opts,stream);
    fclose(stream);
    napi_value r; napi_create_string_utf8(env,buf?buf:"",bsz,&r);
    if(buf) { free(buf); }
    return r;
}


static napi_value ndx_entropy(napi_env env, napi_callback_info info) {
    size_t argc=1; napi_value args[1]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin=get_handle(env,args[0]);
    if(!bin){napi_throw_error(env,NULL,"Invalid handle");return NULL;}
    char *buf=NULL; size_t bsz=0;
    FILE *stream=open_memstream(&buf,&bsz);
    if(!stream){napi_throw_error(env,NULL,"open_memstream failed");return NULL;}
    dax_opts_t opts; memset(&opts,0,sizeof(opts)); opts.color=0;
    dax_entropy_scan(bin,&opts,stream);
    fclose(stream);
    napi_value r; napi_create_string_utf8(env,buf?buf:"",bsz,&r);
    if(buf) { free(buf); }
    return r;
}

static napi_value ndx_rda(napi_env env, napi_callback_info info) {
    size_t argc=2; napi_value args[2]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin=get_handle(env,args[0]);
    if(!bin){napi_throw_error(env,NULL,"Invalid handle");return NULL;}
    char section_name[64]=".text";
    if(argc>=2){napi_valuetype vt;napi_typeof(env,args[1],&vt);
        if(vt==napi_string)get_str_arg(env,args[1],section_name,sizeof(section_name));}
    dax_section_t *sec=NULL;
    for(int i=0;i<bin->nsections;i++)
        if(strcmp(bin->sections[i].name,section_name)==0){sec=&bin->sections[i];break;}
    if(!sec){
        /* Section not found — return empty string (not null) so typeof === 'string' */
        napi_value empty; napi_create_string_utf8(env,"",0,&empty); return empty;
    }
    ensure_symbols(bin);
    char *buf=NULL; size_t bsz=0;
    FILE *stream=open_memstream(&buf,&bsz);
    if(!stream){napi_throw_error(env,NULL,"open_memstream failed");return NULL;}
    dax_opts_t opts; memset(&opts,0,sizeof(opts)); opts.color=0;
    dax_rda_section(bin,sec,sec->vaddr,&opts,stream);
    fclose(stream);
    napi_value r; napi_create_string_utf8(env,buf?buf:"",bsz,&r);
    if(buf) { free(buf); }
    return r;
}

static napi_value ndx_ivf(napi_env env, napi_callback_info info) {
    size_t argc=1; napi_value args[1]; napi_get_cb_info(env,info,&argc,args,NULL,NULL);
    dax_binary_t *bin=get_handle(env,args[0]);
    if(!bin){napi_throw_error(env,NULL,"Invalid handle");return NULL;}
    char *buf=NULL; size_t bsz=0;
    FILE *stream=open_memstream(&buf,&bsz);
    if(!stream){napi_throw_error(env,NULL,"open_memstream failed");return NULL;}
    dax_opts_t opts; memset(&opts,0,sizeof(opts)); opts.color=0;
    dax_ivf_scan(bin,&opts,stream);
    fclose(stream);
    napi_value r; napi_create_string_utf8(env,buf?buf:"",bsz,&r);
    if(buf) { free(buf); }
    return r;
}

NAPI_MODULE_INIT() {
    napi_value fn;
#define REG(name,func) napi_create_function(env,name,NAPI_AUTO_LENGTH,func,NULL,&fn); napi_set_named_property(env,exports,name,fn)
    REG("load",           ndx_load);
    REG("close",          ndx_close);
    REG("info",           ndx_info);
    REG("sections",       ndx_sections);
    REG("symbols",        ndx_symbols);
    REG("functions",      ndx_functions);
    REG("xrefs",          ndx_xrefs);
    REG("xrefsTo",        ndx_xrefs_to);
    REG("xrefsFrom",      ndx_xrefs_from);
    REG("unicodeStrings", ndx_unicode);
    REG("blocks",         ndx_blocks);
    REG("disasm",         ndx_disasm);
    REG("disasmJson",     ndx_disasm_json);
    REG("analyze",        ndx_analyze);
    REG("symAt",          ndx_sym_at);
    REG("funcAt",         ndx_func_at);
    REG("sectionByName",  ndx_section_by_name);
    REG("sectionAt",      ndx_section_at);
    REG("readBytes",      ndx_read_bytes);
    REG("hottestFunctions", ndx_hottest_functions);
    REG("strings",        ndx_strings);
    REG("version",        ndx_version);
    REG("entropy",        ndx_entropy);
    REG("rda",            ndx_rda);
    REG("ivf",            ndx_ivf);
    REG("symexec",        ndx_symexec);
    REG("ssa",            ndx_ssa);
    REG("decompile",      ndx_decompile);
    REG("emulate",        ndx_emulate);
#undef REG
    return exports;
}
