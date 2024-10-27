%{

#include <stdlib.h>
#include "include/global.h"
#include "include/stack.h"
#include "include/syntax.h"

void yyerror(const char *s);
int yylex();

#ifndef DOXYGEN_SHOULD_SKIP_THIS
%}

%locations

%union {
	struct var_name {
		struct node *nd;
		char *name;
	} nd_obj;
}

%token	<nd_obj> IDENTIFIER I_CONSTANT F_CONSTANT STRING_LITERAL FUNC_NAME SIZEOF
%token	<nd_obj> PTR_OP INC_OP DEC_OP LEFT_OP RIGHT_OP LE_OP GE_OP EQ_OP NE_OP
%token	<nd_obj> AND_OP OR_OP MUL_ASSIGN DIV_ASSIGN MOD_ASSIGN ADD_ASSIGN
%token	<nd_obj> SUB_ASSIGN LEFT_ASSIGN RIGHT_ASSIGN AND_ASSIGN
%token	<nd_obj> XOR_ASSIGN OR_ASSIGN
%token	<nd_obj> TYPEDEF_NAME ENUMERATION_CONSTANT

%token	<nd_obj> TYPEDEF EXTERN STATIC AUTO REGISTER INLINE
%token	<nd_obj> CONST RESTRICT VOLATILE
%token	<nd_obj> BOOL CHAR SHORT INT LONG SIGNED UNSIGNED FLOAT DOUBLE VOID
%token	<nd_obj> COMPLEX IMAGINARY
%token	<nd_obj> STRUCT UNION ENUM ELLIPSIS

%token	<nd_obj> CASE DEFAULT IF ELSE SWITCH WHILE DO FOR GOTO CONTINUE BREAK RETURN

%token	<nd_obj> ALIGNAS ALIGNOF ATOMIC GENERIC NORETURN STATIC_ASSERT THREAD_LOCAL

%token	<nd_obj> SECTION
%token	<nd_obj> DEFINE VERSION FUNCTION
%token	<nd_obj> KDC_REGISTER KDC_INT_REGISTER KDC_VARIABLE

%type	<nd_obj> program headers
%type	<nd_obj> functions function_header
%type	<nd_obj> sections section_header section_value
%type	<nd_obj> value value_str function_value
%type	<nd_obj> condition condition_if
%type	<nd_obj> function_argument_list argument_list string_list
%type	<nd_obj> statement body

%start program
%%

program
	: headers functions sections
	{
		struct node *aux = mknode($1.nd, $2.nd, "aux", TYPE_UND);

		$$.nd = mknode(aux, $3.nd, "program", TYPE_APP);
		ctx->head = $$.nd;
	}
	| headers sections
	{
		$$.nd = mknode($1.nd, $2.nd, "program", TYPE_APP);
		ctx->head = $$.nd;
	}
	;

headers
	: VERSION '(' STRING_LITERAL ')' ';'
	{ $$.nd = mknode(NULL, NULL, $3.name, TYPE_VER); }
	| DEFINE IDENTIFIER value
	{ $$.nd = mknode(NULL, $3.nd, $2.name, TYPE_DEF); }
	| TYPEDEF KDC_REGISTER value ';'
	{
		struct node *aux = mknode(NULL, NULL, $2.name, TYPE_REG);

		$$.nd = mknode(aux, $3.nd, "global_typedef", TYPE_TYD);
	}
	| INT IDENTIFIER '[' value ']' '=' '{' argument_list '}' ';'
	{ $$.nd = mknode($4.nd, $8.nd, $2.name, TYPE_ARR); }
	| headers headers
	{ $$.nd = mknode($1.nd, $2.nd, "header", TYPE_UND); }
	| error
	{ ERR("unrecognized global definition\n"); }
	;

functions
	: function_header '{' '}'
	{ $$.nd = mknode($1.nd, NULL, $1.nd->token, TYPE_FUN); }
	| function_header '{' body '}'
	{ $$.nd = mknode($1.nd, $3.nd, $1.nd->token, TYPE_FUN); }
	| functions functions
	{ $$.nd = mknode($1.nd, $2.nd, "function", TYPE_UND); }
	;

function_header
	: IDENTIFIER '(' ')'
	{ $$.nd = mknode($1.nd, NULL, $1.name, TYPE_UND); }
	| IDENTIFIER '(' function_argument_list ')'
	{ $$.nd = mknode($1.nd, $3.nd, $1.name, TYPE_UND); }
	;

sections
	: section_header '{' '}'
	{ $$.nd = mknode($1.nd, NULL, $1.nd->token, TYPE_SEC); }
	| section_header '{' body '}'
	{ $$.nd = mknode($1.nd, $3.nd, $1.nd->token, TYPE_SEC); }
	| sections sections
	{ $$.nd = mknode($1.nd, $2.nd, "section", TYPE_UND); }
	;

section_value
	: I_CONSTANT
	{ $$.nd = mknode(NULL, NULL, $1.name, TYPE_VAL); }
	| IDENTIFIER
	{ $$.nd = mknode(NULL, NULL, $1.name, TYPE_IDA); }
	;

section_header
	: SECTION '(' section_value ')'
	{ $$.nd = mknode($3.nd, NULL, "section", TYPE_UND); }
	| SECTION '(' section_value ',' function_argument_list ')'
	{ $$.nd = mknode($3.nd, $5.nd, "section", TYPE_UND); }
	| error
	{ ERR("unrecognized section name format\n"); }
	;

value
	: I_CONSTANT
	{ $$.nd = mknode(NULL, NULL, $1.name, TYPE_VAL); }
	| KDC_REGISTER
	{ $$.nd = mknode(NULL, NULL, $1.name, TYPE_REG); }
	| KDC_INT_REGISTER
	{ $$.nd = mknode(NULL, NULL, $1.name, TYPE_IRG); }
	| IDENTIFIER
	{ $$.nd = mknode(NULL, NULL, $1.name, TYPE_IDA); }
	| IDENTIFIER '[' value ']'
	{ $$.nd = mknode(NULL, $3.nd, $1.name, TYPE_ARV); }
	| error
	{ ERR("unrecognized statement / value\n"); }
	;

value_str
	: STRING_LITERAL
	{ $$.nd = mknode(NULL, NULL, $1.name, TYPE_STR); }
	;

function_value
	: IDENTIFIER
	{ $$.nd = mknode(NULL, NULL, $1.name, TYPE_VAA); }
	| error
	{ ERR("unrecognized function value variable declaration\n"); }
	;

condition
	: value '<' value
	{ $$.nd = mknode($1.nd, $3.nd, "lt_op", TYPE_IFC); }
	| value '>' value
	{ $$.nd = mknode($1.nd, $3.nd, "gt_op", TYPE_IFC); }
	| value LE_OP value
	{ $$.nd = mknode($1.nd, $3.nd, "le_op", TYPE_IFC); }
	| value GE_OP value
	{ $$.nd = mknode($1.nd, $3.nd, "ge_op", TYPE_IFC); }
	| value EQ_OP value
	{ $$.nd = mknode($1.nd, $3.nd, "eq_op", TYPE_IFC); }
	| value NE_OP value
	{ $$.nd = mknode($1.nd, $3.nd, "ne_op", TYPE_IFC); }
	| value '&' value
	{ $$.nd = mknode($1.nd, $3.nd, "and", TYPE_IFC); }
	| value '^' value
	{ $$.nd = mknode($1.nd, $3.nd, "xor", TYPE_IFC); }
	| value '|' value
	{ $$.nd = mknode($1.nd, $3.nd, "or", TYPE_IFC); }
	| value AND_OP value
	{ $$.nd = mknode($1.nd, $3.nd, "and_op", TYPE_IFC); }
	| value OR_OP value
	{ $$.nd = mknode($1.nd, $3.nd, "or_op", TYPE_IFC); }
	| '~' value
	{ $$.nd = mknode($2.nd, $2.nd, "not_op", TYPE_IFC); }
	| '!' value
	{ $$.nd = mknode($2.nd, $2.nd, "neg_op", TYPE_IFC); }
	| value '+' value
	{ $$.nd = mknode($1.nd, $3.nd, "plus", TYPE_IFC); }
	| value '-' value
	{ $$.nd = mknode($1.nd, $3.nd, "minus", TYPE_IFC); }
	| value '*' value
	{ $$.nd = mknode($1.nd, $3.nd, "mult", TYPE_IFC); }
	| value '/' value
	{ $$.nd = mknode($1.nd, $3.nd, "div", TYPE_IFC); }
	| value '%' value
	{ $$.nd = mknode($1.nd, $3.nd, "mod", TYPE_IFC); }
	| value RIGHT_OP value
	{ $$.nd = mknode($1.nd, $3.nd, "rshift", TYPE_IFC); }
	| value LEFT_OP value
	{ $$.nd = mknode($1.nd, $3.nd, "lshift", TYPE_IFC); }
	;

condition_if
	: condition
	{ $$.nd = $1.nd; }
	| value
	{
		struct node *aux = mknode(NULL, NULL, "0", TYPE_VAL);

		$$.nd = mknode($1.nd, aux, "ne_op", TYPE_IFC);
	}
	;

function_argument_list
	: function_value
	{ $$.nd = mknode($1.nd, NULL, "arguments", TYPE_ARG); }
	| function_value ',' function_argument_list
	{ $$.nd = mknode($1.nd, $3.nd, "arguments", TYPE_ARG); }
	;

argument_list
	: value
	{ $$.nd = mknode($1.nd, NULL, "arguments", TYPE_ARG); }
	| value ',' argument_list
	{ $$.nd = mknode($1.nd, $3.nd, "arguments", TYPE_ARG); }
	;

string_list
	: value_str
	{ $$.nd = mknode($1.nd, NULL, "arguments", TYPE_ARG); }
	;

statement
	: IDENTIFIER '(' argument_list ')'
	{ $$.nd = mknode(NULL, $3.nd, $1.name, TYPE_ID); }
	| IDENTIFIER '(' ')'
	{ $$.nd = mknode(NULL, NULL, $1.name, TYPE_ID); }
	| IDENTIFIER '(' string_list ')'
	{ $$.nd = mknode(NULL, $3.nd, $1.name, TYPE_ID); }
	| TYPEDEF value value
	{ $$.nd = mknode($2.nd, $3.nd, "typedef", TYPE_TYD); }
	| value '=' value
	{ $$.nd = mknode($1.nd, $3.nd, $1.name, TYPE_SET); }
	| value '=' condition
	{ $$.nd = mknode($1.nd, $3.nd, $1.name, TYPE_STM); }
	| INT IDENTIFIER '[' value ']' '=' '{' argument_list '}'
	{ $$.nd = mknode($4.nd, $8.nd, $2.name, TYPE_ARR); }
	| BREAK
	{
		struct node *val_nd = mknode(NULL, NULL, "0", TYPE_BRK);
		struct node *arg_nd = mknode(val_nd, NULL, "arguments", TYPE_ARG);

		$$.nd = mknode(NULL, arg_nd, "BRK", TYPE_ID);
	}
	| RETURN
	{
		struct node *val_nd = mknode(NULL, NULL, "0", TYPE_RET);
		struct node *arg_nd = mknode(val_nd, NULL, "arguments", TYPE_ARG);

		$$.nd = mknode(NULL, arg_nd, "RET", TYPE_ID);
	}
	;

body
	: IF '(' condition_if ')' '{' body '}'
	{
		struct node *if_n = mknode($3.nd, $6.nd, $1.name, TYPE_IFE);

		$$.nd = mknode(if_n, NULL, "if", TYPE_IFE);
	}
	| IF '(' condition_if ')' '{' body '}' ELSE '{' body '}'
	{
		struct node *if_n = mknode($3.nd, $6.nd, $1.name, TYPE_IFE);
		struct node *else_n = mknode($3.nd, $10.nd, $1.name, TYPE_IFE);

		$$.nd = mknode(if_n, else_n, "if-else", TYPE_IFE);
	}
	| IF '(' condition_if ')' '{' body '}' ELSE statement ';'
	{
		struct node *if_n = mknode($3.nd, $6.nd, $1.name, TYPE_IFE);
		struct node *else_n = mknode($3.nd, $9.nd, $1.name, TYPE_IFE);

		$$.nd = mknode(if_n, else_n, "if-else", TYPE_IFE);
	}
	| IF '(' condition_if ')' statement ';' ELSE '{' body '}'
	{
		struct node *if_n = mknode($3.nd, $5.nd, $1.name, TYPE_IFE);
		struct node *else_n = mknode($3.nd, $9.nd, $1.name, TYPE_IFE);

		$$.nd = mknode(if_n, else_n, "if-else", TYPE_IFE);
	}
	| IF '(' condition_if ')' statement ';'
	{
		struct node *if_n = mknode($3.nd, $5.nd, $1.name, TYPE_IFE);

		$$.nd = mknode(if_n, NULL, "if", TYPE_IFE);
	}
	| IF '(' condition_if ')' statement ';' ELSE statement ';'
	{
		struct node *if_n = mknode($3.nd, $5.nd, $1.name, TYPE_IFE);
		struct node *else_n = mknode($3.nd, $8.nd, $1.name, TYPE_IFE);

		$$.nd = mknode(if_n, else_n, "if-else", TYPE_IFE);
	}
	| WHILE '(' condition_if ')' '{' body '}'
	{ $$.nd = mknode($3.nd, $6.nd, $1.name, TYPE_WHI); }
	| WHILE '(' condition_if ')' statement ';'
	{ $$.nd = mknode($3.nd, $5.nd, $1.name, TYPE_WHI); }
	| statement ';'
	{ $$.nd = mknode($1.nd, NULL, "statements", TYPE_STA); }
	| body body
	{ $$.nd = mknode($1.nd, $2.nd, "statements", TYPE_STA); }
	| error
	{ ERR("unrecognized statement\n"); }
	;

%%
#endif /* DOXYGEN_SHOULD_SKIP_THIS */
/*! @file
 * Part of Synopsys Firmware Compiler application.
 */
#include <stdio.h>
#include <stdlib.h>

void yyerror(const char *s)
{
	WAR("parsing error at line %d: %s\n", yylloc.first_line, s);
}
