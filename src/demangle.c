#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "dax.h"

#define DM_BUFSZ 256

typedef struct {
    const char *p;
    const char *end;
    char        out[DM_BUFSZ];
    int         pos;
    char        subs[32][64];
    int         nsubs;
} dm_ctx_t;

static void dm_puts(dm_ctx_t *c, const char *s) {
    while (*s && c->pos < DM_BUFSZ - 1)
        c->out[c->pos++] = *s++;
    c->out[c->pos] = 0;
}

static void dm_putc(dm_ctx_t *c, char ch) {
    if (c->pos < DM_BUFSZ - 1) {
        c->out[c->pos++] = ch;
        c->out[c->pos]   = 0;
    }
}

static int dm_avail(dm_ctx_t *c) {
    return c->p < c->end;
}

static char dm_peek(dm_ctx_t *c) {
    return dm_avail(c) ? *c->p : 0;
}

static char dm_consume(dm_ctx_t *c) {
    return dm_avail(c) ? *c->p++ : 0;
}

static int dm_expect(dm_ctx_t *c, char ch) {
    if (dm_avail(c) && *c->p == ch) { c->p++; return 1; }
    return 0;
}

static int dm_number(dm_ctx_t *c) {
    int n = 0;
    while (dm_avail(c) && isdigit((unsigned char)*c->p))
        n = n * 10 + (dm_consume(c) - '0');
    return n;
}

static void dm_source_name(dm_ctx_t *c) {
    int len = dm_number(c);
    int i;
    char sub[64] = "";
    int spos = 0;
    if (len <= 0 || c->p + len > c->end) return;
    for (i = 0; i < len; i++) {
        char ch = *c->p++;
        dm_putc(c, ch);
        if (spos < 63) sub[spos++] = ch;
    }
    sub[spos] = 0;
    if (c->nsubs < 32) {
        strncpy(c->subs[c->nsubs++], sub, 63);
    }
}

static void dm_type(dm_ctx_t *c);
static void dm_name(dm_ctx_t *c);

static void dm_builtin(dm_ctx_t *c, char code) {
    switch (code) {
        case 'v': dm_puts(c, "void");               break;
        case 'b': dm_puts(c, "bool");               break;
        case 'c': dm_puts(c, "char");               break;
        case 'a': dm_puts(c, "signed char");        break;
        case 'h': dm_puts(c, "unsigned char");      break;
        case 's': dm_puts(c, "short");              break;
        case 't': dm_puts(c, "unsigned short");     break;
        case 'i': dm_puts(c, "int");                break;
        case 'j': dm_puts(c, "unsigned int");       break;
        case 'l': dm_puts(c, "long");               break;
        case 'm': dm_puts(c, "unsigned long");      break;
        case 'x': dm_puts(c, "long long");          break;
        case 'y': dm_puts(c, "unsigned long long"); break;
        case 'n': dm_puts(c, "__int128");           break;
        case 'o': dm_puts(c, "unsigned __int128");  break;
        case 'f': dm_puts(c, "float");              break;
        case 'd': dm_puts(c, "double");             break;
        case 'e': dm_puts(c, "long double");        break;
        case 'g': dm_puts(c, "__float128");         break;
        case 'z': dm_puts(c, "...");                break;
        case 'w': dm_puts(c, "wchar_t");            break;
        default:  dm_putc(c, code);                 break;
    }
}

static void dm_type(dm_ctx_t *c) {
    char ch;
    if (!dm_avail(c)) return;
    ch = dm_peek(c);

    switch (ch) {
        case 'P': dm_consume(c); dm_type(c); dm_puts(c, " *");  return;
        case 'R': dm_consume(c); dm_type(c); dm_puts(c, " &");  return;
        case 'O': dm_consume(c); dm_type(c); dm_puts(c, " &&"); return;
        case 'K': dm_consume(c); dm_puts(c, "const "); dm_type(c); return;
        case 'V': dm_consume(c); dm_puts(c, "volatile "); dm_type(c); return;
        case 'r': dm_consume(c); dm_puts(c, "restrict "); dm_type(c); return;
        case 'A': {
            dm_consume(c);
            if (isdigit((unsigned char)dm_peek(c))) {
                int n = dm_number(c);
                dm_expect(c, '_');
                dm_type(c);
                char tmp[32]; snprintf(tmp, sizeof(tmp), " [%d]", n);
                dm_puts(c, tmp);
            }
            return;
        }
        case 'F': {
            dm_consume(c);
            dm_type(c);
            dm_puts(c, " ()(");
            int first = 1;
            while (dm_avail(c) && dm_peek(c) != 'E') {
                if (!first) dm_puts(c, ", ");
                first = 0;
                dm_type(c);
            }
            dm_expect(c, 'E');
            dm_putc(c, ')');
            return;
        }
        case 'N': case 'Z': dm_name(c); return;
        case 'S': {
            dm_consume(c);
            char next = dm_peek(c);
            if (next == 't') { dm_consume(c); dm_puts(c, "std::"); dm_name(c); }
            else if (next == 's') { dm_consume(c); dm_puts(c, "std::string"); }
            else if (next == 'a') { dm_consume(c); dm_puts(c, "std::allocator"); }
            else if (next == 'b') { dm_consume(c); dm_puts(c, "std::basic_string"); }
            else if (next == 'i') { dm_consume(c); dm_puts(c, "std::istream"); }
            else if (next == 'o') { dm_consume(c); dm_puts(c, "std::ostream"); }
            else if (next == 'd') { dm_consume(c); dm_puts(c, "std::iostream"); }
            else if (isdigit((unsigned char)next) || next == '_') {
                int idx = 0;
                if (next != '_') { idx = dm_number(c) + 1; }
                dm_expect(c, '_');
                if (idx < c->nsubs) dm_puts(c, c->subs[idx]);
                else dm_puts(c, "<sub?>");
            } else {
                dm_putc(c, 'S');
            }
            return;
        }
        default:
            if (isdigit((unsigned char)ch) || ch == 'N' || ch == 'Z') {
                dm_name(c);
            } else {
                dm_consume(c);
                dm_builtin(c, ch);
            }
            return;
    }
}

static void dm_template_args(dm_ctx_t *c) {
    dm_expect(c, 'I');
    dm_putc(c, '<');
    int first = 1;
    while (dm_avail(c) && dm_peek(c) != 'E') {
        if (!first) dm_puts(c, ", ");
        first = 0;
        if (dm_peek(c) == 'L') {
            dm_consume(c);
            dm_type(c);
            dm_putc(c, ' ');
            while (dm_avail(c) && dm_peek(c) != 'E') {
                if (isdigit((unsigned char)dm_peek(c)) || dm_peek(c)=='-')
                    dm_putc(c, dm_consume(c));
                else break;
            }
            dm_expect(c, 'E');
        } else {
            dm_type(c);
        }
    }
    dm_expect(c, 'E');
    dm_puts(c, ">");
}

static void dm_name(dm_ctx_t *c) {
    if (!dm_avail(c)) return;
    char ch = dm_peek(c);

    if (ch == 'N') {
        dm_consume(c);
        int first = 1;
        while (dm_avail(c) && dm_peek(c) != 'E') {
            if (!first) dm_puts(c, "::");
            first = 0;
            if (dm_peek(c) == 'I') {
                dm_template_args(c);
            } else if (isdigit((unsigned char)dm_peek(c))) {
                dm_source_name(c);
            } else if (dm_peek(c) == 'C') {
                dm_consume(c); dm_consume(c);
                int back = c->pos;
                while (back > 0 && c->out[back-1] != ':') back--;
                dm_puts(c, c->out + back);
            } else if (dm_peek(c) == 'D') {
                dm_consume(c); dm_consume(c);
                dm_putc(c, '~');
                int back = c->pos;
                while (back > 0 && c->out[back-1] != ':' && c->out[back-1] != '~') back--;
                dm_puts(c, c->out + back);
            } else {
                break;
            }
        }
        dm_expect(c, 'E');
    } else if (isdigit((unsigned char)ch)) {
        dm_source_name(c);
        if (dm_avail(c) && dm_peek(c) == 'I') {
            dm_template_args(c);
        }
    } else if (ch == 'L') {
        dm_consume(c);
        dm_source_name(c);
        dm_expect(c, 'E');
    } else if (ch == 'S') {
        dm_type(c);
    } else if (ch == 'Z') {
        dm_consume(c);
        dm_name(c);
        dm_expect(c, 'E');
    } else {
        dm_consume(c);
    }
}

static const char *operator_name(const char *p) {
    if (!p[0] || !p[1]) return NULL;
    struct { const char code[3]; const char *name; } ops[] = {
        {"nw","operator new"},     {"na","operator new[]"},
        {"dl","operator delete"},  {"da","operator delete[]"},
        {"ps","operator+"},        {"ng","operator-"},
        {"ad","operator&"},        {"de","operator*"},
        {"co","operator~"},        {"pl","operator+"},
        {"mi","operator-"},        {"ml","operator*"},
        {"dv","operator/"},        {"rm","operator%"},
        {"an","operator&"},        {"or","operator|"},
        {"eo","operator^"},        {"aS","operator="},
        {"pL","operator+="},       {"mI","operator-="},
        {"mL","operator*="},       {"dV","operator/="},
        {"rM","operator%="},       {"aN","operator&="},
        {"oR","operator|="},       {"eO","operator^="},
        {"ls","operator<<"},       {"rs","operator>>"},
        {"lS","operator<<="},      {"rS","operator>>="},
        {"eq","operator=="},       {"ne","operator!="},
        {"lt","operator<"},        {"gt","operator>"},
        {"le","operator<="},       {"ge","operator>="},
        {"ss","operator<=>"},      {"nt","operator!"},
        {"aa","operator&&"},       {"oo","operator||"},
        {"pp","operator++"},       {"mm","operator--"},
        {"cm","operator,"},        {"pm","operator->*"},
        {"pt","operator->"},       {"cl","operator()"},
        {"ix","operator[]"},       {"qu","operator?"},
        {"cv","operator "},        {"li","operator\"\""},
        {"",""}
    };
    int i;
    for (i = 0; ops[i].code[0]; i++) {
        if (p[0] == ops[i].code[0] && p[1] == ops[i].code[1])
            return ops[i].name;
    }
    return NULL;
}

int dax_demangle(const char *mangled, char *out, size_t outsz) {
    dm_ctx_t ctx;
    const char *p;

    if (!mangled || !out || outsz < 4) return -1;

    if (mangled[0] != '_' || mangled[1] != 'Z') {
        strncpy(out, mangled, outsz - 1);
        out[outsz - 1] = 0;
        return 0;
    }

    memset(&ctx, 0, sizeof(ctx));
    p = mangled + 2;
    ctx.p   = p;
    ctx.end = mangled + strlen(mangled);

    if (p[0] == 'T') {
        p++; ctx.p = p;
        if (p[0]=='V') { dm_puts(&ctx,"vtable for "); ctx.p++; }
        else if (p[0]=='T') { dm_puts(&ctx,"VTT for "); ctx.p++; }
        else if (p[0]=='I') { dm_puts(&ctx,"typeinfo for "); ctx.p++; }
        else if (p[0]=='S') { dm_puts(&ctx,"typeinfo name for "); ctx.p++; }
        else if (p[0]=='h') { dm_puts(&ctx,"non-virtual thunk to "); ctx.p++; }
        else if (p[0]=='v') { dm_puts(&ctx,"virtual thunk to "); ctx.p++; }
        else                { dm_puts(&ctx,"special::"); }
        dm_name(&ctx);
    } else if (p[0] == 'G') {
        p++; ctx.p = p;
        if (p[0]=='V') { dm_puts(&ctx,"guard variable for "); ctx.p++; }
        else            { dm_puts(&ctx,"G::"); }
        dm_name(&ctx);
    } else {
        const char *opname = operator_name(p);
        if (opname) {
            dm_puts(&ctx, opname);
            ctx.p += 2;
        } else {
            dm_name(&ctx);
        }
        if (ctx.p < ctx.end && *ctx.p == 'I') {
            dm_template_args(&ctx);
        }
        if (ctx.p < ctx.end) {
            dm_putc(&ctx, '(');
            int first = 1;
            while (ctx.p < ctx.end) {
                if (!first) dm_puts(&ctx, ", ");
                first = 0;
                dm_type(&ctx);
            }
            dm_putc(&ctx, ')');
        }
    }

    if (!ctx.pos) {
        strncpy(out, mangled, outsz - 1);
        out[outsz - 1] = 0;
        return -1;
    }

    strncpy(out, ctx.out, outsz - 1);
    out[outsz - 1] = 0;
    return 0;
}
