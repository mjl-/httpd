%{
include "sys.m";
	sys: Sys;
	print, sprint, fprint, fildes: import sys;
include "draw.m";
include "arg.m";
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "daytime.m";
	daytime: Daytime;
include "dict.m";
	dict: Dictionary;
	Dict: import dict;
include "lists.m";
	lists: Lists;
include "string.m";
	str: String;

# line from the log file
Log: adt {
	d:	ref Dict;

	parse:	fn(s: string): (ref Log, string);
	get:	fn(l: self ref Log, s: string): (string, string);
};


# what comes after keyword "filter"
Expr: adt {
	pick {
	And or Or or Eq or Ne =>
		p0, p1:	cyclic ref Expr;
	Param or Str =>
		s:	string;
	}

	eval:	fn(e: self ref Expr, l: ref Log): int;
	text:	fn(e: self ref Expr): string;
};

# keywords "limit", "sort" & "reverse"
Final: adt {
	pick {
	Limit =>
		n:	int;
	Sort =>
		s:	string;
	Reverse =>
	}

	text:	fn(f: self ref Final): string;
};

# a table, its requirements & progress/state
Table: adt {
	name, descr:	string;
	per:	list of string;
	filter:	ref Expr;
	keep:	list of string;
	final:	list of ref Final;

	rows:	array of array of ref (string, int);
	types:	array of int;

	apply:	fn(t: self ref Table, l: ref Log): string;
	finalize:	fn(t: self ref Table, f: ref Final);
	write:	fn(t: self ref Table, fd: ref Sys->FD): string;
	text:	fn(t: self ref Table): string;
};

YYSTYPE: adt {
	tab, word, str:	string;
	table:	ref Table;
	filter:	ref Expr;
};

YYLEX: adt {
	lval:	YYSTYPE;
	lex:	fn(l: self ref YYLEX): int;
	error:	fn(l: self ref YYLEX, msg: string);
};

%}

%module Logparse {
	init:	fn(nil: ref Draw->Context, args: list of string);
}


%type <filter>	exprs expr param

%token <tab>	TAB
%token <str>	STR
%token <word>	WORD
%token DESCR PER KEEP FILTER SORT LIMIT REVERSE END

%token AND
%token OR
%token EQ NE

%%

top:
	top table { tabs = curtab::tabs; }
	| { tabs = lists->reverse(tabs); }
	;

table:
	TAB { curtab = ref zerotab; curtab.name = $1; } descr pers filters keeps finals
	END {
		curtab.per = lists->reverse(curtab.per);
		curtab.keep = lists->reverse(curtab.keep);
		curtab.per = lists->reverse(curtab.per);
		curtab.final = lists->reverse(curtab.final);
	}
	;

descr:
	DESCR STR { curtab.descr = $2; }
	|
	;

pers:
	pers per
	|
	;

per:
	PER WORD { curtab.per = $2::curtab.per; }
	;

filters:
	filters filter
	|
	;

filter:
	FILTER exprs {
		if(curtab.filter == nil)
			curtab.filter = $2;
		else
			curtab.filter = ref Expr.And(curtab.filter, $2);
	}
	;

exprs:
	expr AND expr	{ $$ = ref Expr.And ($1, $3); }
	| expr OR expr	{ $$ = ref Expr.Or ($1, $3); }
	| expr
	;

expr:
	param EQ param	{ $$ = ref Expr.Eq($1, $3); }
	| param NE param	{ $$ = ref Expr.Ne($1, $3); }
	| param
	;

param:
	WORD	{ $$ = ref Expr.Param ($1); }
	| STR	{ $$ = ref Expr.Str ($1); }
	;

keeps:
	keeps keep
	|
	;

keep:
	KEEP WORD { curtab.keep = $2::curtab.keep; }
	;

finals:
	finals final
	|
	;

final:
	SORT WORD	{ curtab.final = ref Final.Sort ($2)::curtab.final; }
	| LIMIT WORD	{ curtab.final = ref Final.Limit (int $2)::curtab.final; }
	| REVERSE	{ curtab.final = ref Final.Reverse::curtab.final; }
	;

%%

dflag: int;

btab: ref Iobuf;
done: int;
zerotab: Table;

curtab: ref Table;
tabs: list of ref Table;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	bufio = load Bufio Bufio->PATH;
	daytime = load Daytime Daytime->PATH;
	dict = load Dictionary Dictionary->PATH;
	str = load String String->PATH;
	lists = load Lists Lists->PATH;
	arg := load Arg Arg->PATH;

	arg->init(args);
	arg->setusage(arg->progname()+" [-d] tabfile log");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	dflag++;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 2)
		arg->usage();
	tabfile := hd args;
	logfile := hd tl args;

	btab = bufio->open(tabfile, Bufio->OREAD);
	if(btab == nil)
		fail(sprint("open %q: %r", tabfile));

	blog := bufio->open(logfile, Bufio->OREAD);
	if(blog == nil)
		fail(sprint("open %q: %r", logfile));

	done = 0;
	lex := ref YYLEX;
	yyparse(lex);
	warn(sprint("have %d tables", len tabs));
	tabs = lists->reverse(tabs);
	#for(t := tabs; t != nil; t = tl t)
	#	warn((hd t).text()+"\n");

	# for each line in the log file...
	for(;;) {
		line := blog.gets('\n');
		if(line == nil)
			break;
		(l, err) := Log.parse(line);
		if(err != nil)
			fail("parselog: "+err);

		# try each table to see if they "accept" it (by filter expressions)
		for(t := tabs; t != nil; t = tl t) {
			tab := hd t;
			# if accepted, apply the line
			if(tab.filter == nil || tab.filter.eval(l))
				if((err = tab.apply(l)) != nil)
					fail(err);
		}
	}

	# now we reverse/limit/sort
	for(t := tabs; t != nil; t = tl t) {
		tab := hd t;
		for(f := tab.final; f != nil; f = tl f)
			tab.finalize(hd f);
	}

	fd := sys->fildes(1);
	for(t = tabs; t != nil; t = tl t) {
		tab := hd t;
		err := tab.write(fd);
		if(err != nil) {
			warn(sprint("write %q: %s", tab.name, err));
			continue;
		}
		sys->fprint(fd, "\n");
	}
}


YYLEX.error(nil: self ref YYLEX, err: string)
{
	fail("parsing: "+err);
}

YYLEX.lex(lex: self ref YYLEX): int
{
	if(done)
		return -1;
	for(;;){
		c := btab.getc();
		case c {
		'"' =>
			# read until end of string, two consecutive ones escape
			s: string;
			for(;;) {
				case c = btab.getc() {
				Bufio->EOF or Bufio->ERROR =>
					return -1;
				'"' =>
					c = btab.getc();
					if(c != '"') {
						btab.ungetc();
						lex.lval.str = s;
						say("have str");
						return STR;
					}
					s[len s] = '"';
				* =>
					s[len s] = c;
				}
			}

		' ' or '\t' =>
			;
		'\n' =>
			n := 0;
			for(;;) {
				c = btab.getc();
				if(c != '\n')
					break;
				n++;
			}
			btab.ungetc();
			if(n > 0)
				return END;

		'!' =>
			c = btab.getc();
			if(c == '=')
				return NE;
			btab.ungetc();
			return -1;

		'=' =>
			c = btab.getc();
			if(c == '=')
				return EQ;
			btab.ungetc();
			return -1;

		'a' to 'z' or '0' to '9' or '(' or ')' =>
			s: string;
			s[len s] = c;
			for(;;) {
				case c = btab.getc() {
				'a' to 'z' or '0' to '9' or '(' or ')' or ':' =>
					s[len s] = c;
				Bufio->ERROR or Bufio->EOF =>
					return -1;
				* =>
					btab.ungetc();
					if(s[len s-1] == ':') {
						lex.lval.tab = s[:len s-1];
						say("have tab");
						return TAB;
					}

					say(sprint("have bare word %q", s));
					case s {
					"descr" =>	return DESCR;
					"per" =>	return PER;
					"keep" =>	return KEEP;
					"filter" =>	return FILTER;
					"sort" =>	return SORT;
					"limit" =>	return LIMIT;
					"reverse" =>	return REVERSE;
					"and" =>	return AND;
					"or" =>		return OR;
					* =>
						lex.lval.word = s;
						say("have word");
						return WORD;
					}
				}
			}

		Bufio->ERROR =>
			return -1;
		Bufio->EOF =>
			done = 1;
			return END;
		}
	}
}


keys := array[] of {
"msec",
"time",
"fromaddr",
"toaddr",
"method",
"host",
"path",
"httpversion",
"status",
"statusmsg",
"size",
"useragent",
"referer",
"fromdns",
};

Log.parse(s: string): (ref Log, string)
{
	l := str->unquoted(s);
	if(len l != len keys)
		return (nil, sprint("wrong number of tokens, want %d, have %d", len keys, len l));
	v := l2a(l);
	d := ref Dict;
	for(i := 0; i < len keys; i++)
		d.add((keys[i], v[i]));
	return (ref Log (d), nil);
}

mkuseragent(nil: string, l: ref Log): (string, string)
{
	ua := l.get("useragent").t0;
	return (str->splitstrl(ua, " ").t0, nil);
}

bots := array[] of {
"Googlebot",
"msnbot",
"Yahoo! Slurp",
"Yanga WorldSearch Bot",
"ia_archiver",
};
mkbothuman(nil: string, l: ref Log): (string, string)
{
	v := l.get("useragent").t0;
	for(i := 0; i < len bots; i++)
		if(substr(bots[i], v))
			return ("bot", nil);
	return ("human", nil);
}

substr(sub, s: string): int
{
	return str->splitstrl(s, sub).t0 != nil;
}

mkfromip(nil: string, l: ref Log): (string, string)
{
	v := l.get("fromaddr").t0;
	return (str->splitstrl(v, "!").t0, nil);
}

mksubnet16(nil: string, l: ref Log): (string, string)
{
	v := l.get("fromaddr").t0;
	e := sys->tokenize(v, ".").t1;
	return (hd e+"."+hd tl e, nil);
}

mkdnstld(nil: string, l: ref Log): (string, string)
{
	v := l.get("fromdns").t0;
	if(v == nil)
		return ("<no reverse dns>", nil);
	return (str->splitstrr(v, ".").t1, nil);
}

mkdomain(nil: string, l: ref Log): (string, string)
{
	v := l.get("referer").t0;
	if(v == nil)
		return ("<no referer>", nil);
	if(str->prefix("http://", v))
		v = v[len "http://":];
	else if(str->prefix("https://", v))
		v = v[len "https://":];
	else
		return ("<malformed>", nil);
	return (str->splitstrl(v, "/").t0, nil);
}


days := array[] of {
"sun", "mon", "tue", "wed", "thu", "fri", "sat",
};
mkdayofweek(nil: string, l: ref Log): (string, string)
{
	v := int l.get("time").t0;
	tm := daytime->gmt(v);
	return (days[tm.wday], nil);
}

mkdate(nil: string, l: ref Log): (string, string)
{
	v := int l.get("time").t0;
	tm := daytime->gmt(v);
	return (sprint("%04d-%02d-%02d", 1900+tm.year, tm.mon+1, tm.mday), nil);
}

mkhour(nil: string, l: ref Log): (string, string)
{
	v := int l.get("time").t0;
	tm := daytime->gmt(v);
	return (sprint("%02d", tm.hour), nil);
}

mkextension(nil: string, l: ref Log): (string, string)
{
	v := l.get("path").t0;
	rem: string;
	(rem, v) = str->splitr(v, "/.");
	if(rem != nil && rem[len rem-1] == '/')
		v = "";
	else
		v = "."+v;
	return (v, nil);
}

mkmajorstatus(nil: string, l: ref Log): (string, string)
{
	v := l.get("status").t0;
	return (v[0:1], nil);
}

Log.get(l: self ref Log, s: string): (string, string)
{
	specials := array[] of {
	("useragentname(useragent)",	mkuseragent),
	("bothuman(useragent)",		mkbothuman),
	("fromip",			mkfromip),
	("subnet16(fromip)",		mksubnet16),
	("dnstld(dns)",			mkdnstld),
	("domain(referer)",		mkdomain),
	("dayofweek(time)",		mkdayofweek),
	("date(time)",			mkdate),
	("hour(time)",			mkhour),
	("extension(path)",		mkextension),
	("major(status)",		mkmajorstatus),
	};

	v := l.d.lookup(s);
	if(v != nil)
		return (v, nil);

	# might have empty value.  annoying dict interface...
	for(k := l.d.keys(); k != nil; k = tl k)
		if(hd k == s)
			return ("", nil);

	for(i := 0; i < len specials; i++)
		if(specials[i].t0 == s)
			return specials[i].t1(s, l);
	return (nil, "no such key/derivative: "+s);
}


eval(e: ref Expr, l: ref Log): string
{
	pick ee := e {
	And =>
		if(eval(ee.p0, l) != "" && eval(ee.p1, l) != "")
			return "true";
		return "";
	Or =>
		if(eval(ee.p0, l) != "" || eval(ee.p1, l) != "")
			return "true";
		return "";
	Eq =>
		if(eval(ee.p0, l) == eval(ee.p1, l))
			return "true";
		return "";
	Ne =>
		if(eval(ee.p0, l) != eval(ee.p1, l))
			return "true";
		return "";
	Param =>
		(v, err) := l.get(ee.s);
		if(err != nil) {
			warn(sprint("eval %q: %s", ee.s, err));
			return "";
		}
		return v;
	Str =>
		return ee.s;
	}
}

Expr.eval(e: self ref Expr, l: ref Log): int
{
	return eval(e, l) != "";
}

Table.apply(t: self ref Table, l: ref Log): string
{
	# find row, or reuse existing row in case of aggregates
	(row, err) := getrow(t, l);

	i := len t.per;
	for(k := t.keep; err == nil && k != nil; k = tl k)
		err = setcol(row, i++, hd k, l, t.types);
	return err;
}

setcol(row: array of ref (string, int), col: int, k: string, l: ref Log, types: array of int): string
{
	case k {
	"count" =>
		types[col] = 1;
		row[col].t1++;

	"sum(size)" or "avg(size)" =>  # xxx bogus avg() value now
		types[col] = 1;
		v := l.get("size").t0;
		if(v != nil)
			row[col].t1 += int v;

	* =>
		(v, err) := l.get(k);
		if(err != nil)
			return err;
		row[col].t0 = v;
	}
	return nil;
}

getrow(t: ref Table, l: ref Log): (array of ref (string, int), string)
{
	# xxx should be done once during table init...
	if(t.types == nil)
		t.types = array[len t.per+len t.keep] of {* => 0};

	pvs := array[len t.per] of ref (string, int);
	i := 0;
	for(pers := t.per; pers != nil; pers = tl pers) {
		p := hd pers;
		(v, err) := l.get(p);
		if(err != nil)
			return (nil, err);
		pvs[i++] = ref (v, 0);
	}

	# xxx does not depend on per's, but on presence of aggregates
	if(len pvs > 0) {
	nextrow:
		for(i = 0; i < len t.rows; i++) {
			for(j := 0; j < len pvs; j++)
				if(t.rows[i][j].t0 != pvs[j].t0)
					continue nextrow;
			return (t.rows[i], nil);
		}
	}

	ncol := len t.per+len t.keep;

	row := array[ncol] of {* => ref ("", 0)};
	row[:] = pvs;

	nrows := array[len t.rows+1] of array of ref (string, int);
	nrows[:] = t.rows;
	nrows[len t.rows] = row;
	t.rows = nrows;

	return (row, nil);
}

sort[T](a: array of T, ge: ref fn(a, b: T, field, numeric: int): int, field, numeric: int)
{
	for(i := 1; i < len a; i++) {
		tmp := a[i];
		for(j := i; j > 0 && ge(a[j-1], tmp, field, numeric); j--)
			a[j] = a[j-1];
		a[j] = tmp;
	}
}

# higher is first
rowge(a, b: array of ref (string, int), i, numeric: int): int
{
	if(numeric)
		return a[i].t1 < b[i].t1;
	return a[i].t0 < b[i].t0;
}

fieldindex(t: ref Table, s: string): int
{
	i := 0;
	for(l := t.per; l != nil; l = tl l)
		if(hd l == s)
			return i;
		else
			i++;
	for(l = t.keep; l != nil; l = tl l)
		if(hd l == s)
			return i;
		else
			i++;
	raise "no index found for key "+s;
}

Table.finalize(t: self ref Table, f: ref Final)
{
	pick ff := f {
	Sort =>
		col := fieldindex(t, ff.s); # xxx have to enforce somewhere that key to sort on is also in t.per or t.keep
		sort(t.rows, rowge, col, t.types[col]);
	Reverse =>
		for(i := 0; i < len t.rows ; i++)
			(t.rows[i], t.rows[len t.rows-1-i]) = (t.rows[len t.rows-1-i], t.rows[i]);
	Limit =>
		if(len t.rows > ff.n)
			t.rows = t.rows[:ff.n];
	}
}

Table.write(t: self ref Table, fd: ref Sys->FD): string
{
	sys->fprint(fd, "%s: %s\n", t.name, t.descr);
	for(l := t.per; l != nil; l = tl l)
		sys->fprint(fd, "\t%s", hd l);
	for(l = t.keep; l != nil; l = tl l)
		sys->fprint(fd, "\t%s", hd l);
	sys->fprint(fd, "\n");
	for(i := 0; i < len t.rows; i++) {
		for(j := 0; j < len t.types; j++) {
			if(t.types[j])
				sys->fprint(fd, "\t%d", t.rows[i][j].t1);
			else
				sys->fprint(fd, "\t%s", t.rows[i][j].t0);
		}
		sys->fprint(fd, "\n");
	}
	return nil;
}


Table.text(t: self ref Table): string
{
	s := sprint("%s:\n\tdescr \"%s\"\n", t.name, t.descr);

	for(l := t.per; l != nil; l = tl l)
		s += "\tper "+hd l+"\n";

	if(t.filter != nil)
		s += "\tfilter "+t.filter.text()+"\n";

	for(l = t.keep; l != nil; l = tl l)
		s += "\tkeep "+hd l+"\n";

	for(ff := t.final; ff != nil; ff = tl ff)
		s += "\t"+(hd ff).text()+"\n";

	return s;
}

Expr.text(f: self ref Expr): string
{
	pick ff := f {
	And =>
		return ff.p0.text()+" and "+ff.p1.text();
	Or =>
		return ff.p0.text()+" or "+ff.p1.text();
	Eq =>
		return ff.p0.text()+" == "+ff.p1.text();
	Ne =>
		return ff.p0.text()+" != "+ff.p1.text();
	Param =>
		return ff.s;
	Str =>
		return "\""+ff.s+"\"";
	}
}

Final.text(f: self ref Final): string
{
	pick ff := f {
	Sort =>
		return sprint("sort %s", ff.s);
	Limit =>
		return sprint("limit %d", ff.n);
	Reverse =>
		return "reverse";
	}
}

l2a[T](l: list of T): array of T
{
	a := array[len l] of T;
	i := 0;
	for(; l != nil; l = tl l)
		a[i++] = hd l;
	return a;
}

say(s: string)
{
	if(dflag)
		warn(s);
}

warn(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
}

fail(s: string)
{
	warn(s);
	raise "fail:"+s;
}
