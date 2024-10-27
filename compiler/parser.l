%{
#include <stdio.h>
#include "parser.tab.h"

#define YY_USER_ACTION		yylloc.first_line = yylloc.last_line = yylineno;

extern void yyerror(const char *);  /* prints grammar violation message */
extern int sym_type(const char *);  /* returns type from symbol table */

#define sym_type(identifier) IDENTIFIER /* with no symbol table, fake it */
#define insert_type(t) yylval.nd_obj.name = strdup(t)
#define insert_type_n(t, n) yylval.nd_obj.name = strndup(t, n)

static void comment(void);
static int check_type(void);

#ifndef DOXYGEN_SHOULD_SKIP_THIS
%}

%e  1019
%p  2807
%n  371
%k  284
%a  1213
%o  1117

O   [0-7]
D   [0-9]
NZ  [1-9]
L   [a-zA-Z_]
A   [a-zA-Z_0-9]
H   [a-fA-F0-9]
HP  (0[xX])
E   ([Ee][+-]?{D}+)
P   ([Pp][+-]?{D}+)
FS  (f|F|l|L)
IS  (((u|U)(l|L|ll|LL)?)|((l|L|ll|LL)(u|U)?))
CP  (u|U|L)
SP  (u8|u|U|L)
ES  (\\(['"\?\\abfnrtv]|[0-7]{1,3}|x[a-fA-F0-9]+))
WS  [ \t\v\n\f]

%option yylineno

%%
"/*"                                    { comment(); }
"//".*                                    { /* consume //-comment */ }

"#define"				{ insert_type(yytext); return(DEFINE); }
"auto"					{ insert_type(yytext); return(AUTO); }
"break"					{ insert_type(yytext); return(BREAK); }
"case"					{ insert_type(yytext); return(CASE); }
"char"					{ insert_type(yytext); return(CHAR); }
"const"					{ insert_type(yytext); return(CONST); }
"continue"				{ insert_type(yytext); return(CONTINUE); }
"default"				{ insert_type(yytext); return(DEFAULT); }
"do"					{ insert_type(yytext); return(DO); }
"double"				{ insert_type(yytext); return(DOUBLE); }
"else"					{ insert_type(yytext); return(ELSE); }
"enum"					{ insert_type(yytext); return(ENUM); }
"extern"				{ insert_type(yytext); return(EXTERN); }
"float"					{ insert_type(yytext); return(FLOAT); }
"for"					{ insert_type(yytext); return(FOR); }
"goto"					{ insert_type(yytext); return(GOTO); }
"if"					{ insert_type(yytext); return(IF); }
"inline"				{ insert_type(yytext); return(INLINE); }
"int"					{ insert_type(yytext); return(INT); }
"u32"					{ insert_type(yytext); return(INT); }
"long"					{ insert_type(yytext); return(LONG); }
"register"				{ insert_type(yytext); return(REGISTER); }
"restrict"				{ insert_type(yytext); return(RESTRICT); }
"return"				{ insert_type(yytext); return(RETURN); }
"short"					{ insert_type(yytext); return(SHORT); }
"signed"				{ insert_type(yytext); return(SIGNED); }
"sizeof"				{ insert_type(yytext); return(SIZEOF); }
"static"				{ insert_type(yytext); return(STATIC); }
"struct"				{ insert_type(yytext); return(STRUCT); }
"switch"				{ insert_type(yytext); return(SWITCH); }
"typedef"				{ insert_type(yytext); return(TYPEDEF); }
"union"					{ insert_type(yytext); return(UNION); }
"unsigned"				{ insert_type(yytext); return(UNSIGNED); }
"void"					{ insert_type(yytext); return(VOID); }
"volatile"				{ insert_type(yytext); return(VOLATILE); }
"while"					{ insert_type(yytext); return(WHILE); }
"_Alignas"                              { insert_type(yytext); return ALIGNAS; }
"_Alignof"                              { insert_type(yytext); return ALIGNOF; }
"_Atomic"                               { insert_type(yytext); return ATOMIC; }
"_Bool"                                 { insert_type(yytext); return BOOL; }
"_Complex"                              { insert_type(yytext); return COMPLEX; }
"_Generic"                              { insert_type(yytext); return GENERIC; }
"_Imaginary"                            { insert_type(yytext); return IMAGINARY; }
"_Noreturn"                             { insert_type(yytext); return NORETURN; }
"_Static_assert"                        { insert_type(yytext); return STATIC_ASSERT; }
"_Thread_local"                         { insert_type(yytext); return THREAD_LOCAL; }
"__func__"                              { insert_type(yytext); return FUNC_NAME; }
"__section"				{ insert_type(yytext); return SECTION; }
"__version"				{ insert_type(yytext); return VERSION; }
"__function"				{ insert_type(yytext); return FUNCTION; }

"r"{D}{D}				{ insert_type(yytext); return KDC_REGISTER; }
"__r"{D}{D}				{ insert_type(yytext); return KDC_INT_REGISTER; }
{L}{A}*					{ insert_type(yytext); return check_type(); }

{HP}{H}+{IS}?				{ insert_type(yytext); return I_CONSTANT; }
{NZ}{D}*{IS}?				{ insert_type(yytext); return I_CONSTANT; }
"0"{O}*{IS}?				{ insert_type(yytext); return I_CONSTANT; }
{CP}?"'"([^'\\\n]|{ES})+"'"		{ insert_type(yytext); return I_CONSTANT; }

{D}+{E}{FS}?				{ insert_type(yytext); return F_CONSTANT; }
{D}*"."{D}+{E}?{FS}?			{ insert_type(yytext); return F_CONSTANT; }
{D}+"."{E}?{FS}?			{ insert_type(yytext); return F_CONSTANT; }
{HP}{H}+{P}{FS}?			{ insert_type(yytext); return F_CONSTANT; }
{HP}{H}*"."{H}+{P}{FS}?			{ insert_type(yytext); return F_CONSTANT; }
{HP}{H}+"."{P}{FS}?			{ insert_type(yytext); return F_CONSTANT; }

({SP}?\"([^"\\\n]|{ES})*\"{WS}*)+	{ insert_type_n(yytext + 1, yyleng - 2); return STRING_LITERAL; }

"..."					{ return ELLIPSIS; }
">>="					{ return RIGHT_ASSIGN; }
"<<="					{ return LEFT_ASSIGN; }
"+="					{ return ADD_ASSIGN; }
"-="					{ return SUB_ASSIGN; }
"*="					{ return MUL_ASSIGN; }
"/="					{ return DIV_ASSIGN; }
"%="					{ return MOD_ASSIGN; }
"&="					{ return AND_ASSIGN; }
"^="					{ return XOR_ASSIGN; }
"|="					{ return OR_ASSIGN; }
">>"					{ return RIGHT_OP; }
"<<"					{ return LEFT_OP; }
"++"					{ return INC_OP; }
"--"					{ return DEC_OP; }
"->"					{ return PTR_OP; }
"&&"					{ return AND_OP; }
"||"					{ return OR_OP; }
"<="					{ return LE_OP; }
">="					{ return GE_OP; }
"=="					{ return EQ_OP; }
"!="					{ return NE_OP; }
";"					{ return ';'; }
("{"|"<%")				{ return '{'; }
("}"|"%>")				{ return '}'; }
","					{ return ','; }
":"					{ return ':'; }
"="					{ return '='; }
"("					{ return '('; }
")"					{ return ')'; }
("["|"<:")				{ return '['; }
("]"|":>")				{ return ']'; }
"."					{ return '.'; }
"&"					{ return '&'; }
"!"					{ return '!'; }
"~"					{ return '~'; }
"-"					{ return '-'; }
"+"					{ return '+'; }
"*"					{ return '*'; }
"/"					{ return '/'; }
"%"					{ return '%'; }
"<"					{ return '<'; }
">"					{ return '>'; }
"^"					{ return '^'; }
"|"					{ return '|'; }
"?"					{ return '?'; }

{WS}+					{ /* whitespace separates tokens */ }
.					{ /* discard bad characters */ }

%%
#endif /* DOXYGEN_SHOULD_SKIP_THIS */
int yywrap(void)        /* called at end of input */
{
    return 1;           /* terminate now */
}

static void comment(void)
{
    int c;

    while ((c = input()) != 0)
        if (c == '*')
        {
            while ((c = input()) == '*')
                ;

            if (c == '/')
                return;

            if (c == 0)
                break;
        }
    yyerror("unterminated comment");
}

static int check_type(void)
{
    switch (sym_type(yytext))
    {
    case TYPEDEF_NAME:                /* previously defined */
        return TYPEDEF_NAME;
    case ENUMERATION_CONSTANT:        /* previously defined */
        return ENUMERATION_CONSTANT;
    default:                          /* includes undefined */
        return IDENTIFIER;
    }
}
