#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "y64asm.h"

line_t* line_head = NULL;
line_t* line_tail = NULL;
int     lineno    = 0;

#define DEBUG 0

#define err_print(_s, _a...)       \
    do {                           \
        if (lineno < 0)            \
            fprintf(stderr,        \
                    "[--]: "_s     \
                    "\n",          \
                    ##_a);         \
        else                       \
            fprintf(stderr,        \
                    "[L%d]: "_s    \
                    "\n",          \
                    lineno, ##_a); \
    } while (0);

#define log(_s, _a...)                \
    if (DEBUG) {                      \
        do {                          \
            if (lineno < 0)           \
                printf("[--]: "_s     \
                       "\n",          \
                       ##_a);         \
            else                      \
                printf("[L%d]: "_s    \
                       "\n",          \
                       lineno, ##_a); \
        } while (0);                  \
    }

int64_t vmaddr = 0; /* vm addr */
char    global_buf[MAX_INSLEN];
byte_t  byte_buf[1];

/* register table */
const reg_t  reg_table[REG_NONE] = { { "%rax", REG_RAX, 4 }, { "%rcx", REG_RCX, 4 }, { "%rdx", REG_RDX, 4 }, { "%rbx", REG_RBX, 4 }, { "%rsp", REG_RSP, 4 },
                                    { "%rbp", REG_RBP, 4 }, { "%rsi", REG_RSI, 4 }, { "%rdi", REG_RDI, 4 }, { "%r8", REG_R8, 3 },   { "%r9", REG_R9, 3 },
                                    { "%r10", REG_R10, 4 }, { "%r11", REG_R11, 4 }, { "%r12", REG_R12, 4 }, { "%r13", REG_R13, 4 }, { "%r14", REG_R14, 4 } };
const reg_t* find_register(char* name) {
    int i;
    for (i = 0; i < REG_NONE; i++)
        if (!strncmp(name, reg_table[i].name, reg_table[i].namelen))
            return &reg_table[i];
    return NULL;
}

/* instruction set */
instr_t instr_set[] = {
    { "nop", 3, HPACK(I_NOP, F_NONE), 1 },
    { "halt", 4, HPACK(I_HALT, F_NONE), 1 },
    { "rrmovq", 6, HPACK(I_RRMOVQ, F_NONE), 2 },
    { "cmovle", 6, HPACK(I_RRMOVQ, C_LE), 2 },
    { "cmovl", 5, HPACK(I_RRMOVQ, C_L), 2 },
    { "cmove", 5, HPACK(I_RRMOVQ, C_E), 2 },
    { "cmovne", 6, HPACK(I_RRMOVQ, C_NE), 2 },
    { "cmovge", 6, HPACK(I_RRMOVQ, C_GE), 2 },
    { "cmovg", 5, HPACK(I_RRMOVQ, C_G), 2 },
    { "irmovq", 6, HPACK(I_IRMOVQ, F_NONE), 10 },
    { "rmmovq", 6, HPACK(I_RMMOVQ, F_NONE), 10 },
    { "mrmovq", 6, HPACK(I_MRMOVQ, F_NONE), 10 },
    { "addq", 4, HPACK(I_ALU, A_ADD), 2 },
    { "subq", 4, HPACK(I_ALU, A_SUB), 2 },
    { "andq", 4, HPACK(I_ALU, A_AND), 2 },
    { "xorq", 4, HPACK(I_ALU, A_XOR), 2 },
    { "jmp", 3, HPACK(I_JMP, C_YES), 9 },
    { "jle", 3, HPACK(I_JMP, C_LE), 9 },
    { "jl", 2, HPACK(I_JMP, C_L), 9 },
    { "je", 2, HPACK(I_JMP, C_E), 9 },
    { "jne", 3, HPACK(I_JMP, C_NE), 9 },
    { "jge", 3, HPACK(I_JMP, C_GE), 9 },
    { "jg", 2, HPACK(I_JMP, C_G), 9 },
    { "call", 4, HPACK(I_CALL, F_NONE), 9 },
    { "ret", 3, HPACK(I_RET, F_NONE), 1 },
    { "pushq", 5, HPACK(I_PUSHQ, F_NONE), 2 },
    { "popq", 4, HPACK(I_POPQ, F_NONE), 2 },
    { ".byte", 5, HPACK(I_DIRECTIVE, D_DATA), 1 },
    { ".word", 5, HPACK(I_DIRECTIVE, D_DATA), 2 },
    { ".long", 5, HPACK(I_DIRECTIVE, D_DATA), 4 },
    { ".quad", 5, HPACK(I_DIRECTIVE, D_DATA), 8 },
    { ".pos", 4, HPACK(I_DIRECTIVE, D_POS), 0 },
    { ".align", 6, HPACK(I_DIRECTIVE, D_ALIGN), 0 },
    { NULL, 1, 0, 0 }  // end
};

instr_t* find_instr(char* name) {
    int i;
    for (i = 0; instr_set[i].name; i++)
        if (strncmp(instr_set[i].name, name, instr_set[i].len) == 0)
            return &instr_set[i];
    return NULL;
}

/* symbol table (don't forget to init and finit it) */
symbol_t* symtab = NULL;

/*
 * find_symbol: scan table to find the symbol
 * args
 *     name: the name of symbol
 *
 * return
 *     symbol_t: the 'name' symbol
 *     NULL: not exist
 */
symbol_t* find_symbol(char* name) {
    // log("Going to find symbol %s\n", name);
    if (symtab == NULL) {
        return NULL;
    }

    symbol_t* node = symtab;

    while (node != NULL) {
        // log("strcmp: %s, %s\n", node->name, name);
        if (strcmp(node->name, name) == 0) {
            // log("Successfully found.\n");
            return node;
        }
        node = node->next;
    }
    // log("No symbol found.\n");
    return NULL;
}

/*
 * add_symbol: add a new symbol to the symbol table
 * args
 *     name: the name of symbol
 *
 * return
 *     0: success
 *     -1: error, the symbol has exist
 */
int add_symbol(char* name, int64_t addr) {
    /* check duplicate */

    if (find_symbol(name) != NULL) {
        err_print("Dup symbol:%s", name);
        return -1;
        // duplicate symbol here
    }

    /* copy name buffer (don't forget to free it)*/
    char* name_buf = calloc(MAX_INSLEN, sizeof(char));
    strcpy(name_buf, name);

    /* add the new symbol_t to symbol table */
    if (symtab == NULL) {
        symtab       = calloc(1, sizeof(symbol_t));
        symtab->addr = addr;
        symtab->name = name_buf;
        symtab->next = NULL;
        log("Added First Symbol %s at %ld\n", name, addr);
        return 0;
    }

    symbol_t* node = symtab;
    while (node->next != NULL) {
        node = node->next;
    }

    node->next       = calloc(1, sizeof(symbol_t));
    node->next->addr = addr;
    node->next->name = name_buf;
    log("Added Symbol %s at %ld\n", name, addr);
    return 0;
}

/* relocation table (don't forget to init and finit it) */
reloc_t* reltab = NULL;

/*
 * add_reloc: add a new relocation to the relocation table
 * args
 *     name: the name of relocation
 *
 */
int add_reloc(char* name, bin_t* bin) {

    /* create new reloc_t (don't forget to free it)*/

    char* name_buf = calloc(MAX_INSLEN, sizeof(char));
    strcpy(name_buf, name);

    /* add the new reloc_t to symbol table */

    if (reltab == NULL) {
        reltab         = calloc(1, sizeof(reloc_t));
        reltab->name   = name_buf;
        reltab->y64bin = bin;
        log("Add First reloc called %s\n", reltab->name);
        return 0;
    }

    reloc_t* node = reltab;

    while (node->next != NULL) {
        // Since mentioned above, to see if it's the end of the node tree,
        // You must check its name pointer (char *) but not the next pointer itself.
        // It's always initialized.
        node = node->next;
    }

    node->next         = calloc(1, sizeof(reloc_t));
    node->next->name   = name_buf;
    node->next->y64bin = bin;
    log("Add reloc called %s\n", node->next->name);

    return 0;
}

/* macro for parsing y64 assembly code */
#define IS_DIGIT(s) ((*(s) >= '0' && *(s) <= '9') || *(s) == '-' || *(s) == '+')
#define IS_LETTER(s) ((*(s) >= 'a' && *(s) <= 'z') || (*(s) >= 'A' && *(s) <= 'Z'))
#define IS_COMMENT(s) (*(s) == '#')
#define IS_REG(s) (*(s) == '%')
#define IS_IMM(s) (*(s) == '$')

#define IS_BLANK(s) (*(s) == ' ' || *(s) == '\t')
#define IS_END(s) (*(s) == '\0')

#define SKIP_BLANK(s)                     \
    do {                                  \
        while (!IS_END(s) && IS_BLANK(s)) \
            (s)++;                        \
    } while (0);

/* return value from different parse_xxx function */
typedef enum { PARSE_ERR = -1, PARSE_REG, PARSE_DIGIT, PARSE_SYMBOL, PARSE_MEM, PARSE_DELIM, PARSE_INSTR, PARSE_LABEL } parse_t;

// /*
//  * parse_delim: parse an expected delimiter token (e.g., ',')
//  * args
//  *     ptr: point to the start of string
//  *
//  * return
//  *     PARSE_DELIM: success, move 'ptr' to the first char after token
//  *     PARSE_ERR: error, the value of 'ptr' and 'delim' are undefined
//  */
parse_t parse_delim(char** ptr) {
    while (**ptr == ' ' || **ptr == '\t') {
        ++(*ptr);
    }
    if (**ptr == ',') {
        ++(*ptr);
    }
    else {
        err_print("Invalid ','");
        return PARSE_ERR;
    }
    while (**ptr == ' ' || **ptr == '\t') {
        ++(*ptr);
    }

    return PARSE_DELIM;
}

/*
 * parse_reg: parse an expected register token (e.g., '%rax')
 * args
 *     ptr: point to the start of string
 *     regid: point to the regid of register
 *
 * return
 *     PARSE_REG: success, move 'ptr' to the first char after token,
 *                         and store the regid to 'regid'
 *     PARSE_ERR: error, the value of 'ptr' and 'regid' are undefined
 */
parse_t parse_reg(char** ptr, regid_t* regid) {
    if (!IS_REG(*ptr)) {
        err_print("Invalid REG");
        return PARSE_ERR;
    }
    int i;
    for (i = 0; i < 15; ++i) {
        if (strncmp(reg_table[i].name, *ptr, reg_table[i].namelen) == 0) {
            *regid = reg_table[i].id;
            *ptr += reg_table[i].namelen;
            return PARSE_REG;
        }
    }
    err_print("Invalid REG");
    return PARSE_ERR;
}

// /*
//  * parse_symbol: parse an expected symbol token (e.g., 'Main')
//  * args
//  *     ptr: point to the start of string
//  *     name: point to the name of symbol (should be allocated in this function)
//  *
//  * return
//  *     PARSE_SYMBOL: success, move 'ptr' to the first char after token,
//  *                               and allocate and store name to 'name'
//  *     PARSE_ERR: error, the value of 'ptr' and 'name' are undefined
//  */
// parse_t parse_symbol(char** ptr, char** name) {
//     /* skip the blank and check */

//     /* allocate name and copy to it */

//     /* set 'ptr' and 'name' */

//     return PARSE_ERR;
// }

// /*
//  * parse_digit: parse an expected digit token (e.g., '0x100')
//  * args
//  *     ptr: point to the start of string
//  *     value: point to the value of digit
//  *
//  * return
//  *     PARSE_DIGIT: success, move 'ptr' to the first char after token
//  *                            and store the value of digit to 'value'
//  *     PARSE_ERR: error, the value of 'ptr' and 'value' are undefined
//  */
// parse_t parse_digit(char** ptr, long* value) {
//     /* skip the blank and check */

//     /* calculate the digit, (NOTE: see strtoll()) */

//     /* set 'ptr' and 'value' */

//     return PARSE_ERR;
// }

/*
 * parse_imm: parse an expected immediate token (e.g., '$0x100' or 'STACK')
 * args
 *     ptr: point to the start of string
 *     name: point to the name of symbol (should be allocated in this function)
 *     value: point to the value of digit
 *
 * return
 *     PARSE_DIGIT: success, the immediate token is a digit,
 *                            move 'ptr' to the first char after token,
 *                            and store the value of digit to 'value'
 *     PARSE_SYMBOL: success, the immediate token is a symbol,
 *                            move 'ptr' to the first char after token,
 *                            and allocate and store name to 'name'
 *     PARSE_ERR: error, the value of 'ptr', 'name' and 'value' are undefined
 */
parse_t parse_imm(char** ptr, char** name, long* value) {
    /* skip the blank and check */
    while (**ptr == ' ' || **ptr == '\t') {
        ++(*ptr);
    }
    /* if IS_IMM, then parse the digit */
    if (IS_IMM(*ptr)) {
        ++(*ptr);
        char* result;
        log("Gotta $ like integer: %s\n", *ptr);

        *value = strtoul(*ptr, &result, 0);
        if (*ptr == result) {
            err_print("Invalid Immediate");
            return PARSE_ERR;
        }
        *ptr = result;
        return PARSE_DIGIT;
    }
    else if (IS_DIGIT(*ptr)) {
        log("Gotta no $ like integer: %s\n", *ptr);

        *value = strtoul(*ptr, ptr, 0);
        return PARSE_DIGIT;
    }
    /* if IS_LETTER, then parse the symbol */
    if (IS_LETTER(*ptr)) {

        *name = calloc(MAX_INSLEN, sizeof(char));
        log("going to find symbol %s\n", *ptr);

        int len = 0;

        while ((*ptr)[len] != ',' && (*ptr)[len] != '\t' && (*ptr)[len] != '\n' && (*ptr)[len] != '\0' && (*ptr)[len] != ' ') {
            ++len;
        }

        log("Str = %s Now len = %d\n", *ptr, len);

        strncpy(*name, *ptr, len);

        symbol_t* sym = find_symbol(*name);

        if (sym != NULL) {
            log("found symbol %s at %ld\n", sym->name, sym->addr);
            *value = sym->addr;
        }

        *ptr += len;
        // Skip the Label words
        return PARSE_SYMBOL;
    }
    /* set 'ptr' and 'name' or 'value' */

    return PARSE_ERR;
}

// /*
//  * parse_mem: parse an expected memory token (e.g., '8(%rbp)')
//  * args
//  *     ptr: point to the start of string
//  *     value: point to the value of digit
//  *     regid: point to the regid of register
//  *
//  * return
//  *     PARSE_MEM: success, move 'ptr' to the first char after token,
//  *                          and store the value of digit to 'value',
//  *                          and store the regid to 'regid'
//  *     PARSE_ERR: error, the value of 'ptr', 'value' and 'regid' are undefined
//  */
// parse_t parse_mem(char** ptr, long* value, regid_t* regid) {
//     /* skip the blank and check */

//     /* calculate the digit and register, (ex: (%rbp) or 8(%rbp)) */

//     /* set 'ptr', 'value' and 'regid' */

//     return PARSE_ERR;
// }

// /*
//  * parse_data: parse an expected data token (e.g., '0x100' or 'array')
//  * args
//  *     ptr: point to the start of string
//  *     name: point to the name of symbol (should be allocated in this function)
//  *     value: point to the value of digit
//  *
//  * return
//  *     PARSE_DIGIT: success, data token is a digit,
//  *                            and move 'ptr' to the first char after token,
//  *                            and store the value of digit to 'value'
//  *     PARSE_SYMBOL: success, data token is a symbol,
//  *                            and move 'ptr' to the first char after token,
//  *                            and allocate and store name to 'name'
//  *     PARSE_ERR: error, the value of 'ptr', 'name' and 'value' are undefined
//  */
// parse_t parse_data(char** ptr, char** name, long* value) {
//     /* skip the blank and check */

//     /* if IS_DIGIT, then parse the digit */

//     /* if IS_LETTER, then parse the symbol */

//     /* set 'ptr', 'name' and 'value' */

//     return PARSE_ERR;
// }

// /*
//  * parse_label: parse an expected label token (e.g., 'Loop:')
//  * args
//  *     ptr: point to the start of string
//  *     name: point to the name of symbol (should be allocated in this function)
//  *
//  * return
//  *     PARSE_LABEL: success, move 'ptr' to the first char after token
//  *                            and allocate and store name to 'name'
//  *     PARSE_ERR: error, the value of 'ptr' is undefined
//  */
// parse_t parse_label(char** ptr, char** name) {
//     /* skip the blank and check */

//     /* allocate name and copy to it */

//     /* set 'ptr' and 'name' */

//     return PARSE_ERR;
// }

/*
 * parse_line: parse a line of y64 code (e.g., 'Loop: mrmovq (%rcx), %rsi')
 * (you could combine above parse_xxx functions to do it)
 * args
 *     line: point to a line_t data with a line of y64 assembly code
 *
 * return
 *     PARSE_XXX: success, fill line_t with assembled y64 code
 *     PARSE_ERR: error, try to print err information (e.g., instr type and line number)
 */
type_t parse_line(line_t* line) {

    char* start = line->y64asm;
    while (*start == ' ' || *start == '\t') {
        ++start;
    }
    /* skip blank and check IS_END */
    char* end = start;
    while (*end != '#' && *end != '\0') {
        ++end;
    }

    /* is a comment ? */
    char* ins_word          = calloc(MAX_INSLEN, sizeof(char));
    char* free_use_ins_word = ins_word;
    char* label_word        = calloc(MAX_INSLEN, sizeof(char));

    log("going to copy %ld\n", end - start);
    strncpy(ins_word, start, end - start);
    log("Eaten %s\n", ins_word);

    if (strlen(ins_word) == 0) {
        line->type = TYPE_COMM;
        goto _CLEAN_UP;
    }
    line->type = TYPE_INS;

    char* org_ins_word = ins_word;
    char* separator    = NULL;

    bin_t binary;
    log("Org ins word = %s\n", org_ins_word);

    while (*org_ins_word != '\0' && *org_ins_word != '\n') {
        if (*org_ins_word == ':') {
            separator = org_ins_word;
            break;
        }
        ++org_ins_word;
    }

    if (separator != NULL) {

        strncpy(label_word, ins_word, separator - ins_word);

        log("A label here! label = %s\n", label_word);
        log("add symbol %s at %ld\n", label_word, vmaddr);

        if (add_symbol(label_word, vmaddr) == -1) {
            // failed to add symbol
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        binary.addr  = vmaddr;
        binary.bytes = 0;

        line->type   = TYPE_INS;
        line->y64bin = binary;

        unsigned counter = 0;
        while (*org_ins_word != '\0') {
            if (*org_ins_word != ' ' && *org_ins_word != '\t') {
                ++counter;
            }
            ++org_ins_word;
        }
        if (counter < 3) {
            return TYPE_COMM;
        }

        ins_word = separator + 1;
        while (*ins_word == ' ' || *ins_word == '\t') {
            ++ins_word;
        }
    }

    instr_t instr = { NULL, 1, 0, 0 };
    int     i;
    for (i = 0; i < 34; ++i) {
        if (strncmp(instr_set[i].name, ins_word, instr_set[i].len) == 0) {
            instr = instr_set[i];
            log("Matched %d, %s\n", i, instr_set[i].name);
            break;
        }
    }

    if (instr.name == NULL) {
        line->type = TYPE_ERR;
        goto _CLEAN_UP;
    }

    // Initialize bytes array
    binary.bytes = instr.bytes;

    // Update instruction address
    binary.addr = vmaddr;

    // Update global virtual machine address
    vmaddr += binary.bytes;

    // Parse parameters
    switch (i) {
    // no parameter. directly write instr code.
    case 0:   // nop
    case 1:   // halt
    case 24:  // ret
    {
        binary.codes[0] = instr.code;
        line->type      = TYPE_INS;
    } break;

    // one or two registers as parameters, write two of them in one byte.
    case 2:   // rrmovq
    case 3:   // cmovle
    case 4:   // cmovl
    case 5:   // cmove
    case 6:   // cmovne
    case 7:   // cmovge
    case 8:   // cmovg
    case 12:  // addq
    case 13:  // subq
    case 14:  // andq
    case 15:  // xorq
    case 25:  // pushq
    case 26:  // popq
    {
        char* funcode = ins_word + instr_set[i].len;
        // Skip the command head.
        while (*funcode == ' ' || *funcode == '\t') {
            ++funcode;
        }
        log("funcode = %s\n", funcode);
        regid_t register_a, register_b;
        binary.codes[0] = instr.code;
        if (parse_reg(&funcode, &register_a) == PARSE_ERR) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        // ins id 25 and 26 (push & pop) doesn't require the second register
        if (i == 25 || i == 26) {
            register_b = 0xf;
            goto _SKIP_PARSE_2;
        }

        if (parse_delim(&funcode) != PARSE_DELIM) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        if (parse_reg(&funcode, &register_b) == PARSE_ERR) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }
    _SKIP_PARSE_2:;
        log("rega = %d, regb = %d\n", register_a, register_b);
        binary.codes[0] = instr.code;
        binary.codes[1] = HPACK(register_a, register_b);
        line->type      = TYPE_INS;

    } break;

    case 9:  // irmovq
    {
        char* funcode = ins_word + instr_set[i].len;
        // Skip the command head.
        while (*funcode == ' ' || *funcode == '\t') {
            ++funcode;
        }
        log("funcode = %s\n", funcode);
        regid_t register_b;
        binary.codes[0] = instr.code;

        char* name;
        long  imm_value = -1;

        int parse_result = parse_imm(&funcode, &name, &imm_value);
        if (parse_result == PARSE_ERR) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        else if (parse_result == PARSE_SYMBOL) {
            if (imm_value < 0) {
                log("In irmovq, name = %s\n", name);
                if (add_reloc(name, &line->y64bin) == -1) {
                    line->type = TYPE_ERR;
                    goto _CLEAN_UP;
                }
            }
        }

        log("Parsed imm num: %ld, name (if any) = %s\n", imm_value, name);
        log("Following funcode = %s\n", funcode);
        if (parse_delim(&funcode) != PARSE_DELIM) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        if (parse_reg(&funcode, &register_b) == PARSE_ERR) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        log("reg = %d\n", register_b);
        binary.codes[0] = instr.code;
        binary.codes[1] = HPACK(0xF, register_b);

        // forcefully reinterprete the pointer
        *( long* )(binary.codes + 2) = imm_value;
        line->type                   = TYPE_INS;
    } break;

    case 10:  // rmmovq
    {
        char* funcode = ins_word + instr_set[i].len;
        // Skip the command head.
        while (*funcode == ' ' || *funcode == '\t') {
            ++funcode;
        }

        regid_t register_a, register_b;
        long    imm_num = 0;

        if (parse_reg(&funcode, &register_a) == PARSE_ERR) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        if (parse_delim(&funcode) != PARSE_DELIM) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        if (sscanf(funcode, "%ld(%s)", &imm_num, global_buf) == 2) {
            // type 233(%register)
            log("match type num(reg)\n");
            imm_num = strtol(funcode, &funcode, 0);
        }

        if (*funcode == '(') {
            funcode += 1;  // skip '('
        }
        else {
            err_print("Invalid MEM");
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }
        if (parse_reg(&funcode, &register_b) == PARSE_ERR) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        if (*funcode == ')') {
            funcode += 1;  // skip ')'
        }
        else {
            err_print("Invalid MEM");
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        binary.codes[0] = instr.code;
        binary.codes[1] = HPACK(register_a, register_b);

        // forcefully reinterprete the pointer
        *( long* )(binary.codes + 2) = imm_num;
        line->type                   = TYPE_INS;
    } break;

    case 11:  // mrmovq
    {
        char* funcode = ins_word + instr_set[i].len;
        // Skip the command head.
        while (*funcode == ' ' || *funcode == '\t') {
            ++funcode;
        }

        regid_t register_a, register_b;
        long    imm_num = 0;

        if (sscanf(funcode, "%ld(%s)", &imm_num, global_buf) == 2) {
            // type 233(%register)
            log("match type num(reg)\n");
            imm_num = strtol(funcode, &funcode, 0);
        }

        if (*funcode == '(') {
            funcode += 1;  // skip '('
        }
        else {
            err_print("Invalid MEM");
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        if (parse_reg(&funcode, &register_b) == PARSE_ERR) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        if (*funcode == ')') {
            funcode += 1;  // skip ')'
        }
        else {
            err_print("Invalid MEM");
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        if (parse_delim(&funcode) != PARSE_DELIM) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        if (parse_reg(&funcode, &register_a) == PARSE_ERR) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }

        binary.codes[0] = instr.code;
        binary.codes[1] = HPACK(register_a, register_b);

        // forcefully reinterprete the pointer
        *( long* )(binary.codes + 2) = imm_num;
        line->type                   = TYPE_INS;
    } break;

        // parameter is an immediate number style:

    case 16:  // jmp
    case 17:  // jle
    case 18:  // jl
    case 19:  // je
    case 20:  // jne
    case 21:  // jge
    case 22:  // jg
    case 23:  // call
    {
        char* funcode = ins_word + instr_set[i].len;
        // Skip the command head.
        while (*funcode == ' ' || *funcode == '\t') {
            ++funcode;
        }
        char* name;
        long  imm_value = -2;

        if (parse_imm(&funcode, &name, &imm_value) != PARSE_SYMBOL) {
            err_print("Invalid DEST");
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }
        if (imm_value < 0) {
            if (add_reloc(name, &line->y64bin) == -1) {
                line->type = TYPE_ERR;
                goto _CLEAN_UP;
            }
            log("Gotta symbol called %s\n", name);
            // requires a relocated
        }
        else {
            log("Gotta imm value = %ld\n", imm_value);
        }
        binary.codes[0] = instr.code;

        // forcefully reinterprete the pointer
        *( long* )(binary.codes + 1) = imm_value;
        // memcpy(binary.codes + 1, &imm_value, 8);
        line->type = TYPE_INS;
    } break;

    // data filling instructions
    case 27:  // .byte
    {
        char* funcode = ins_word + instr_set[i].len;
        // Skip the command head.
        while (*funcode == ' ' || *funcode == '\t') {
            ++funcode;
        }

        long imm_value = 0;
        imm_value      = strtol(funcode, &funcode, 0);

        memcpy(&binary.codes[0], &imm_value, 1);
        line->type = TYPE_INS;
    } break;
    case 28:  // .word
    {
        char* funcode = ins_word + instr_set[i].len;
        // Skip the command head.
        while (*funcode == ' ' || *funcode == '\t') {
            ++funcode;
        }

        long imm_value = 0;
        imm_value      = strtol(funcode, &funcode, 0);

        memcpy(&binary.codes[0], &imm_value, 2);
        line->type = TYPE_INS;
    } break;
    case 29:  // .long
    {
        char* funcode = ins_word + instr_set[i].len;
        // Skip the command head.
        while (*funcode == ' ' || *funcode == '\t') {
            ++funcode;
        }

        char* name;
        long  imm_value = -1;

        int parse_result = parse_imm(&funcode, &name, &imm_value);
        if (parse_result == PARSE_ERR) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }
        else if (parse_result == PARSE_SYMBOL) {
            if (imm_value == -1) {
                log("Prepare reloc. name = %s\n", name);
                if (add_reloc(name, &line->y64bin) == -1) {
                    line->type = TYPE_ERR;
                    goto _CLEAN_UP;
                }
            }
        }

        memcpy(&binary.codes[0], &imm_value, 4);
        line->type = TYPE_INS;
    } break;
    case 30:  // .quad
    {
        char* funcode = ins_word + instr_set[i].len;
        // Skip the command head.
        while (*funcode == ' ' || *funcode == '\t') {
            ++funcode;
        }

        // log("funcode = %s\n", funcode);
        char* name;
        long  imm_value = -1;

        int parse_result = parse_imm(&funcode, &name, &imm_value);
        if (parse_result == PARSE_ERR) {
            line->type = TYPE_ERR;
            goto _CLEAN_UP;
        }
        else if (parse_result == PARSE_SYMBOL) {
            if (imm_value == -1) {
                log("Prepare reloc. name = %s\n", name);
                if (add_reloc(name, &line->y64bin) == -1) {
                    line->type = TYPE_ERR;
                    goto _CLEAN_UP;
                }
            }
        }

        memcpy(&binary.codes[0], &imm_value, 8);
        line->type = TYPE_INS;
        // log("Got quad %ld\n", imm_value);
        // *( long* )binary.codes = imm_value;
    } break;

    case 31:  // .pos
    {
        char* funcode = ins_word + instr_set[i].len;
        // Skip the command head.
        while (*funcode == ' ' || *funcode == '\t') {
            ++funcode;
        }

        int64_t imm_value = strtoll(funcode, &funcode, 0);
        log(".pos at %ld\n", imm_value);

        vmaddr      = imm_value;
        binary.addr = vmaddr;
        line->type  = TYPE_INS;
    } break;

    case 32:  // .align
    {
        char* funcode = ins_word + instr_set[i].len;
        // Skip the command head.
        while (*funcode == ' ' || *funcode == '\t') {
            ++funcode;
        }

        int64_t imm_value = strtoll(funcode, &funcode, 0);
        log("Got align scale %ld\n", imm_value);

        if (imm_value < 1) {
            line->type = TYPE_ERR;
        }

        int len = 0;
        while ((vmaddr + len) % imm_value != 0) {
            ++len;
        }

        vmaddr += len;
        binary.addr = vmaddr;
        line->type  = TYPE_INS;
    } break;
    }

    // set binary struct
    line->y64bin = binary;

_CLEAN_UP:;
    free(free_use_ins_word);
    free(label_word);
    if (DEBUG) {
        // Under DEBUG mode, always assume the parse_line is successful
        // in order to print the debug message.
        return TYPE_INS;
    }
    return line->type;
}

/*
 * assemble: assemble an y64 file (e.g., 'asum.ys')
 * args
 *     in: point to input file (an y64 assembly file)
 *
 * return
 *     0: success, assmble the y64 file to a list of line_t
 *     -1: error, try to print err information (e.g., instr type and line number)
 */
int assemble(FILE* in) {
    static char asm_buf[MAX_INSLEN]; /* the current line of asm code */
    line_t*     line;
    int         slen;
    char*       y64asm;

    /* read y64 code line-by-line, and parse them to generate raw y64 binary code list */
    while (fgets(asm_buf, MAX_INSLEN, in) != NULL) {
        slen = strlen(asm_buf);
        while ((asm_buf[slen - 1] == '\n') || (asm_buf[slen - 1] == '\r')) {
            asm_buf[--slen] = '\0'; /* replace terminator */
        }

        /* store y64 assembly code */
        y64asm = ( char* )malloc(sizeof(char) * (slen + 1));  // free in finit
        strcpy(y64asm, asm_buf);

        line = ( line_t* )malloc(sizeof(line_t));  // free in finit
        memset(line, '\0', sizeof(line_t));

        line->type   = TYPE_COMM;
        line->y64asm = y64asm;
        line->next   = NULL;

        line_tail->next = line;
        line_tail       = line;
        lineno++;

        if (parse_line(line) == TYPE_ERR) {
            return -1;
        }
    }

    lineno = -1;
    return 0;
}

/*
 * relocate: relocate the raw y64 binary code with symbol address
 *
 * return
 *     0: success
 *     -1: error, try to print err information (e.g., addr and symbol)
 */
int relocate(void) {
    if (reltab == NULL) {
        return 0;
    }

    reloc_t* rtmp = NULL;

    rtmp = reltab;

    while (rtmp != NULL) {
        /* find symbol */
        symbol_t* result = find_symbol(rtmp->name);

        /* relocate y64bin according itype */

        if (result != NULL) {
            log("Prepare relocate of %s: at %ld\n", rtmp->name, result->addr);
            *( long* )(rtmp->y64bin->codes + rtmp->y64bin->bytes - 8) = ( long )result->addr;
        }
        else {
            log("Can't find tried relocate of %s\n", rtmp->name);
            err_print("Unknown symbol:'%s'", rtmp->name);
            return -1;
        }

        /* next */
        rtmp = rtmp->next;
    }
    return 0;
}

/*
 * binfile: generate the y64 binary file
 * args
 *     out: point to output file (an y64 binary file)
 *
 * return
 *     0: success
 *     -1: error
 */
int binfile(FILE* out) {

    /* prepare image with y64 binary code */
    line_t* tmp       = line_head->next;
    int64_t last_addr = 0;
    while (tmp != NULL) {
        if (tmp->y64bin.bytes == 0) {
            tmp = tmp->next;
            continue;
        }
        int i;

        // log("Find gap %ld between %ld.\n", tmp->y64bin.addr, last_addr);
        for (i = 0; i < tmp->y64bin.addr - last_addr; ++i) {
            fwrite(byte_buf, sizeof(byte_t), 1, out);
        }

        log("Put %d gap bytes.\n", i);

        if (fwrite(tmp->y64bin.codes, sizeof(byte_t), tmp->y64bin.bytes, out) != tmp->y64bin.bytes) {
            return -1;
        }

        // log("addr = %ld, bytes = %d\n", tmp->y64bin.addr, tmp->y64bin.bytes);

        last_addr = tmp->y64bin.addr + tmp->y64bin.bytes;

        tmp = tmp->next;
    }
    /* binary write y64 code to output file (NOTE: see fwrite()) */

    return 0;
}

/* whether print the readable output to screen or not ? */
bool_t screen = FALSE;

static void hexstuff(char* dest, int value, int len) {
    int i;
    for (i = 0; i < len; i++) {
        char c;
        int  h            = (value >> 4 * i) & 0xF;
        c                 = h < 10 ? h + '0' : h - 10 + 'a';
        dest[len - i - 1] = c;
    }
}

void print_line(line_t* line) {
    char buf[32];

    /* line format: 0xHHH: cccccccccccc | <line> */
    if (line->type == TYPE_INS) {
        bin_t* y64bin = &line->y64bin;
        int    i;

        strcpy(buf, "  0x000:                      | ");

        hexstuff(buf + 4, y64bin->addr, 3);
        if (y64bin->bytes > 0)
            for (i = 0; i < y64bin->bytes; i++)
                hexstuff(buf + 9 + 2 * i, y64bin->codes[i] & 0xFF, 2);
    }
    else {
        strcpy(buf, "                              | ");
    }

    printf("%s%s\n", buf, line->y64asm);
}

/*
 * print_screen: dump readable binary and assembly code to screen
 * (e.g., Figure 4.8 in ICS book)
 */
void print_screen(void) {
    line_t* tmp = line_head->next;
    while (tmp != NULL) {
        print_line(tmp);
        tmp = tmp->next;
    }
}

/* init and finit */
void init(void) {
    // reltab = ( reloc_t* )calloc(1, sizeof(reloc_t));  // free in finit

    // symtab = ( symbol_t* )calloc(1, sizeof(symbol_t));  // free in finit

    line_head = ( line_t* )calloc(1, sizeof(line_t));  // free in finit

    line_tail = line_head;
    lineno    = 0;
}

void finit(void) {

    if (reltab == NULL) {
        goto _SKIP_FREE_RELTAB;
    }
    reloc_t* rtmp = NULL;
    do {
        rtmp = reltab->next;
        if (reltab->name)
            free(reltab->name);
        free(reltab);
        reltab = rtmp;
    } while (reltab);

_SKIP_FREE_RELTAB:;

    if (symtab == NULL) {
        goto _SKIP_FREE_SYMTAB;
    }
    symbol_t* stmp = NULL;
    do {
        stmp = symtab->next;
        if (symtab->name)
            free(symtab->name);
        free(symtab);
        symtab = stmp;
    } while (symtab);
_SKIP_FREE_SYMTAB:;

    line_t* ltmp = NULL;
    do {
        ltmp = line_head->next;
        if (line_head->y64asm)
            free(line_head->y64asm);
        free(line_head);
        line_head = ltmp;
    } while (line_head);
}

static void usage(char* pname) {
    printf("Usage: %s [-v] file.ys\n", pname);
    printf("   -v print the readable output to screen\n");
    exit(0);
}

int main(int argc, char* argv[]) {
    int   rootlen;
    char  infname[512];
    char  outfname[512];
    int   nextarg = 1;
    FILE *in = NULL, *out = NULL;

    if (argc < 2)
        usage(argv[0]);

    if (argv[nextarg][0] == '-') {
        char flag = argv[nextarg][1];
        switch (flag) {
        case 'v':
            screen = TRUE;
            nextarg++;
            break;
        default:
            usage(argv[0]);
        }
    }

    /* parse input file name */
    rootlen = strlen(argv[nextarg]) - 3;
    /* only support the .ys file */
    if (strcmp(argv[nextarg] + rootlen, ".ys"))
        usage(argv[0]);

    if (rootlen > 500) {
        err_print("File name too long");
        exit(1);
    }

    /* init */
    init();

    /* assemble .ys file */
    strncpy(infname, argv[nextarg], rootlen);
    strcpy(infname + rootlen, ".ys");
    in = fopen(infname, "r");
    if (!in) {
        err_print("Can't open input file '%s'", infname);
        exit(1);
    }

    if (assemble(in) < 0) {
        err_print("Assemble y64 code error");
        fclose(in);
        exit(1);
    }
    fclose(in);

    /* relocate binary code */
    if (relocate() < 0) {
        err_print("Relocate binary code error");
        exit(1);
    }

    /* generate .bin file */
    strncpy(outfname, argv[nextarg], rootlen);
    strcpy(outfname + rootlen, ".bin");
    out = fopen(outfname, "wb");
    if (!out) {
        err_print("Can't open output file '%s'", outfname);
        exit(1);
    }

    if (binfile(out) < 0) {
        err_print("Generate binary file error");
        fclose(out);
        exit(1);
    }
    fclose(out);

    /* print to screen (.yo file) */
    if (screen)
        print_screen();

    /* finit */
    finit();
    return 0;
}
