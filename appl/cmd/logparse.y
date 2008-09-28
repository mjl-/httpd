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
	time:	int;

	parse:	fn(s: string): (ref Log, string);
	get:	fn(l: self ref Log, s: string): (string, string);
};


# what comes after keyword "match"
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
	Sort or Normalise =>
		s:	string;
	Reverse =>
	Lump =>
		s, cutoff, str:	string;
	}

	text:	fn(f: self ref Final): string;
};

# a table, its requirements & progress/state
Table: adt {
	name, descr:	string;
	match:	ref Expr;
	per:	list of string;
	keep:	list of string;
	final:	list of ref Final;

	rows:	array of array of ref (string, int, int, int);  # string value, int value, extra values (used by avg)
	types:	array of int;

	colnames:	fn(t: self ref Table): list of string;
	apply:	fn(t: self ref Table, l: ref Log): string;
	finalize:	fn(t: self ref Table, f: ref Final);
	averages:	fn(t: self ref Table);
	write:	fn(t: self ref Table, fd: ref Sys->FD): string;
	writetabbed:	fn(t: self ref Table, fd: ref Sys->FD): string;
	text:	fn(t: self ref Table): string;
};

YYSTYPE: adt {
	tab, word, str:	string;
	table:	ref Table;
	match:	ref Expr;
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


%type <match>	exprs expr param

%token <tab>	TAB
%token <str>	STR
%token <word>	WORD
%token DESCR PER KEEP MATCH SORT LIMIT REVERSE NORMALISE LUMP END

%token AND
%token OR
%token EQ NE

%%

top:
	top table { tabs = curtab::tabs; }
	| { tabs = lists->reverse(tabs); }
	;

table:
	TAB { curtab = ref zerotab; curtab.name = $1; } descr matches pers keeps finals
	END {
		curtab.per = lists->reverse(curtab.per);
		curtab.keep = lists->reverse(curtab.keep);
		curtab.final = lists->reverse(curtab.final);
	}
	;

descr:
	DESCR STR { curtab.descr = $2; }
	|
	;

matches:
	matches match
	|
	;

match:
	MATCH exprs {
		if(curtab.match == nil)
			curtab.match = $2;
		else
			curtab.match = ref Expr.And(curtab.match, $2);
	}
	;

pers:
	pers per
	|
	;

per:
	PER WORD { curtab.per = $2::curtab.per; }
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
	KEEP WORD { 
		if(!isaggregate($2) && len curtab.per != 0 && !has($2, curtab.per))
			fail(sprint("%s:%d: cannot have non-aggregate 'keep' key %q that is not specified as 'per'", tabfile, lineno, $2));
		curtab.keep = $2::curtab.keep;
	}
	;

finals:
	finals final
	|
	;

final:
	SORT WORD	{
		if(fieldindex(curtab, $2) < 0)
			fail(sprint("%s:%d: sort key %#q must be in 'per' or 'keep' statement too", tabfile, lineno, $2));
		curtab.final = ref Final.Sort ($2)::curtab.final;
	}
	| LIMIT WORD	{ curtab.final = ref Final.Limit (int $2)::curtab.final; }
	| REVERSE	{ curtab.final = ref Final.Reverse::curtab.final; }
	| NORMALISE WORD	{
		if(fieldindex(curtab, $2) < 0)
			fail(sprint("%s:%d: normalise key %#q must be in 'per' or 'keep' statement too", tabfile, lineno, $2));
		curtab.final = ref Final.Normalise ($2)::curtab.final;
	}
	| LUMP WORD WORD STR {
		if(fieldindex(curtab, $2) < 0)
			fail(sprint("%s:%d: lump key %#q must be in 'per' or 'keep' statement too", tabfile, lineno, $2));
		if(str->toint($3, 10).t1 != nil)
			fail(sprint("%s:%d: bad threshold, must be numeric", tabfile, lineno));
		curtab.final = ref Final.Lump ($2, $3, $4)::curtab.final;
	}
	;

%%

dflag: int;
qflag: int;

btab: ref Iobuf;
done: int;
zerotab: Table;

curtab: ref Table;
tabs: list of ref Table;
lineno := 1;

Searchblocksize: con big (32*1024);

tabfile, logfile: string;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	bufio = load Bufio Bufio->PATH;
	daytime = load Daytime Daytime->PATH;
	dict = load Dictionary Dictionary->PATH;
	str = load String String->PATH;
	lists = load Lists Lists->PATH;
	arg := load Arg Arg->PATH;

	starttime := endtime := -1;

	arg->init(args);
	arg->setusage(arg->progname()+" [-dq] [-s starttime] [-e endtime] tabfile log");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	dflag++;
		's' =>	starttime = int arg->earg();
		'e' =>	endtime = int arg->earg();
		'q' =>	qflag++;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 2)
		arg->usage();
	tabfile = hd args;
	logfile = hd tl args;

	btab = bufio->open(tabfile, Bufio->OREAD);
	if(btab == nil)
		fail(sprint("open %q: %r", tabfile));

	blog := bufio->open(logfile, Bufio->OREAD);
	if(blog == nil)
		fail(sprint("open %q: %r", logfile));

	done = 0;
	lex := ref YYLEX;
	yyparse(lex);

	tabs = lists->reverse(tabs);
	if(dflag) {
		for(t := tabs; t != nil; t = tl t)
			warn((hd t).text()+"\n");
	}

	# seek to starttime if there is one
	if(starttime >= 0) {
		start := big 0;
		end := blog.seek(start, Bufio->SEEKEND);

		while((diff := end-start) >= big 2*Searchblocksize) {
			mid := start + diff/big 2;
			blog.seek(mid, Bufio->SEEKSTART);
			blog.gets('\n');
			line := blog.gets('\n');
			if(line != nil)
				(l, err) := Log.parse(line);
			if(line == nil || err != nil)
				break;  # current "start" is just fine

			if(l.time >= starttime)
				end = mid;
			else
				start = mid;
		}

		blog.seek(start, Bufio->SEEKSTART);
		blog.gets('\n');
	}

	# for each line in the log file...
	for(;;) {
		line := blog.gets('\n');
		if(line == nil)
			break;
		(l, err) := Log.parse(line);
		if(err != nil)
			fail("parselog: "+err);

		if(starttime >= 0 && l.time < starttime)
			continue;
		if(endtime >= 0 && l.time > endtime)
			break;

		# try each table to see if they "accept" it (by match expressions)
		for(t := tabs; t != nil; t = tl t) {
			tab := hd t;
			if(tab.match == nil || tab.match.eval(l))
				if((err = tab.apply(l)) != nil)
					fail(err);
		}
	}

	# now we reverse/limit/sort/normalise/lump and then recalculate averages
	for(t := tabs; t != nil; t = tl t) {
		tab := hd t;
		for(f := tab.final; f != nil; f = tl f)
			tab.finalize(hd f);

		tab.averages();
	}

	fd := sys->fildes(1);
	for(t = tabs; t != nil; t = tl t) {
		tab := hd t;
		err := "";
		if(qflag)
			err = tab.write(fd);
		else
			err = tab.writetabbed(fd);
		if(err != nil) {
			warn(sprint("write %q: %s", tab.name, err));
			continue;
		}
		sys->fprint(fd, "\n");
	}
}


YYLEX.error(nil: self ref YYLEX, err: string)
{
	fail(sprint("%s:%d: %s", tabfile, lineno, err));
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
			lineno++;
			n := 0;
			for(;;) {
				c = btab.getc();
				if(c != '\n')
					break;
				lineno++;
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
				Bufio->ERROR =>
					return -1;
				* =>
					if(c != Bufio->EOF)
						btab.ungetc();
					if(s[len s-1] == ':') {
						lex.lval.tab = s[:len s-1];
						return TAB;
					}

					case s {
					"descr" =>	return DESCR;
					"per" =>	return PER;
					"keep" =>	return KEEP;
					"match" =>	return MATCH;
					"sort" =>	return SORT;
					"limit" =>	return LIMIT;
					"reverse" =>	return REVERSE;
					"normalise" =>	return NORMALISE;
					"lump" =>	return LUMP;
					"and" =>	return AND;
					"or" =>		return OR;
					* =>
						lex.lval.word = s;
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
	time := int v[1];
	return (ref Log (d, time), nil);
}


substr(sub, s: string): int
{
	return str->splitstrl(s, sub).t1 != nil;
}

aggrs := array[] of {
"count", "sum(size)", "avg(size)",
};
isaggregate(s: string): int
{
	for(i := 0; i < len aggrs; i++)
		if(aggrs[i] == s)
			return 1;
	return 0;
}

isavg(s: string): int
{
	return s == "avg(size)";
}

Log.get(l: self ref Log, s: string): (string, string)
{
	val := l.d.lookup(s);
	if(val != nil)
		return (val, nil);

	# might have empty value.  annoying dict interface...
	for(k := l.d.keys(); k != nil; k = tl k)
		if(hd k == s)
			return ("", nil);

	case s {
	"useragentname(useragent)" =>
		ua := l.get("useragent").t0;
		return (str->splitstrl(ua, " ").t0, nil);

	"bothuman(useragent)" =>
		bots := array[] of {
		"bot",
		"yahoo! slurp",
		};
		v := str->tolower(l.get("useragent").t0);
		for(i := 0; i < len bots; i++)
			if(substr(bots[i], v))
				return ("bot", nil);
		return ("human", nil);

	"fromip" =>
		v := l.get("fromaddr").t0;
		return (str->splitstrl(v, "!").t0, nil);

	"subnet16(fromip)" =>
		v := l.get("fromaddr").t0;
		e := sys->tokenize(v, ".").t1;
		return (hd e+"."+hd tl e, nil);

	"dnstld(dns)" =>
		v := l.get("fromdns").t0;
		if(v == nil)
			return ("<no reverse dns>", nil);
		return (str->splitstrr(v, ".").t1, nil);

	"domain(referer)" =>
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

	"dayofweek(time)" =>
		days := array[] of {
		"sun", "mon", "tue", "wed", "thu", "fri", "sat",
		};
		tm := daytime->gmt(l.time);
		return (days[tm.wday], nil);

	"date(time)" =>
		tm := daytime->gmt(l.time);
		return (sprint("%04d-%02d-%02d", 1900+tm.year, tm.mon+1, tm.mday), nil);

	"hour(time)" =>
		tm := daytime->gmt(l.time);
		return (sprint("%02d", tm.hour), nil);

	"week(time)" =>
		tm := daytime->gmt(l.time);
		week := 1+tm.yday/7;
		firstsat := tm.yday%7 + (6-tm.wday);
		if(firstsat != 6 && tm.yday > firstsat)
			week++;
		return (string week, nil);

	"month(time)" =>
		months := array[] of {
		"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"
		};
		tm := daytime->gmt(l.time);
		return (months[tm.mon], nil);

	"extension(path)" =>
		v := l.get("path").t0;
		rem: string;
		(rem, v) = str->splitr(v, "/.");
		if(rem != nil && rem[len rem-1] == '/')
			v = "";
		else
			v = "."+v;
		return (v, nil);

	"major(status)" =>
		v := l.get("status").t0;
		return (v[0:1], nil);

	* =>
		return (nil, "no such key/derivative: "+s);
	}
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


Table.colnames(t: self ref Table): list of string
{
	v: list of string;
	for(l := t.per; l != nil; l = tl l)
		v = hd l::v;
	for(l = t.keep; l != nil; l = tl l)
		v = hd l::v;
	return lists->reverse(v);
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

# NOTE: keep isaggregate() in sync!
setcol(row: array of ref (string, int, int, int), col: int, k: string, l: ref Log, types: array of int): string
{
	case k {
	"count" =>
		types[col] = 1;
		row[col].t1++;

	"sum(size)" =>
		types[col] = 1;
		v := l.get("size").t0;
		if(v != nil)
			row[col].t1 += int v;

	"avg(size)" =>
		types[col] = 1;
		v := l.get("size").t0;
		if(v != nil) {
			row[col].t2 += int v;
			row[col].t3++;
			row[col].t1 = row[col].t2/row[col].t3;
		}

	* =>
		(v, err) := l.get(k);
		if(err != nil)
			return err;
		row[col].t0 = v;
	}
	return nil;
}

getrow(t: ref Table, l: ref Log): (array of ref (string, int, int, int), string)
{
	# xxx should be done once during table init...
	if(t.types == nil)
		t.types = array[len t.per+len t.keep] of {* => 0};

	pvs := array[len t.per] of ref (string, int, int, int);
	i := 0;
	for(pers := t.per; pers != nil; pers = tl pers) {
		p := hd pers;
		(v, err) := l.get(p);
		if(err != nil)
			return (nil, err);
		pvs[i++] = ref (v, 0, 0, 0);
	}

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

	row := array[ncol] of {* => ref ("", 0, 0, 0)};
	row[:] = pvs;

	nrows := array[len t.rows+1] of array of ref (string, int, int, int);
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
rowge(a, b: array of ref (string, int, int, int), i, numeric: int): int
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
	raise "unknown field requested: "+s;
}

Table.finalize(t: self ref Table, f: ref Final)
{
	if(t.rows == nil || len t.rows == 0)
		return;
	pick ff := f {
	Sort =>
		col := fieldindex(t, ff.s);
		sort(t.rows, rowge, col, t.types[col]);
	Limit =>
		if(len t.rows > ff.n)
			t.rows = t.rows[:ff.n];
	Reverse =>
		for(i := 0; i < len t.rows ; i++)
			(t.rows[i], t.rows[len t.rows-1-i]) = (t.rows[len t.rows-1-i], t.rows[i]);
	Normalise =>
		col := fieldindex(t, ff.s);
		if(t.types[col] != 1)
			fail(sprint("cannot normalise a non-integer"));
		total := 0;
		for(i := 0; i < len t.rows; i++)
			total += t.rows[i][col].t1;
		for(i = 0; i < len t.rows; i++)
			t.rows[i][col].t1 = 1000*t.rows[i][col].t1/total;
	Lump =>
		col := fieldindex(t, ff.s);
		if(t.types[col] != 1)
			fail(sprint("cannot lump a non-integer"));
		cutoff := int ff.cutoff;
		first := -1;
		i := 0;
		while(i < len t.rows) {
			r := t.rows[i];
			if(r[col].t1 <= cutoff) {
				if(first < 0) {
					first = i;
					for(j := 0; j < len t.types; j++)
						r[j].t0 = ff.str;
				} else {
					t.rows[first][col].t1 += r[col].t1;
					t.rows[first][col].t2 += r[col].t2;
					t.rows[first][col].t3 += r[col].t3;
					t.rows[i:] = t.rows[i+1:];
					t.rows = t.rows[:len t.rows-1];
					continue;
				}
			}
			i++;
		}
	}
}

Table.averages(t: self ref Table)
{
	i := 0;
	for(l := t.colnames(); l != nil; l = tl l) {
		if(isavg(hd l)) {
			for(j := 0; j < len t.rows; j++) {
				cell := t.rows[j][i];
				if(cell.t3 > 0)
					cell.t1 = cell.t2/cell.t3;
			}
		}
		i++;
	}
}

Table.write(t: self ref Table, fd: ref Sys->FD): string
{
	sys->fprint(fd, "%s: %s\n", t.name, t.descr);

	sys->fprint(fd, "%s\n", str->quoted(t.colnames()));
	for(i := 0; i < len t.rows; i++) {
		v: list of string;
		for(j := 0; j < len t.types; j++) {
			if(t.types[j])
				v = string t.rows[i][j].t1::v;
			else
				v = t.rows[i][j].t0::v;
		}
		sys->fprint(fd, "%s\n", str->quoted(lists->reverse(v)));
	}
	return nil;
}

Table.writetabbed(t: self ref Table, fd: ref Sys->FD): string
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

	if(t.match != nil)
		s += "\tmatch "+t.match.text()+"\n";

	for(l := t.per; l != nil; l = tl l)
		s += "\tper "+hd l+"\n";

	for(l = t.keep; l != nil; l = tl l)
		s += "\tkeep "+hd l+"\n";

	for(ff := t.final; ff != nil; ff = tl ff)
		s += "\t"+(hd ff).text()+"\n";

	return s;
}

Expr.text(e: self ref Expr): string
{
	pick ee := e {
	And =>
		return "("+ee.p0.text()+" and "+ee.p1.text()+")";
	Or =>
		return "("+ee.p0.text()+" or "+ee.p1.text()+")";
	Eq =>
		return "("+ee.p0.text()+" == "+ee.p1.text()+")";
	Ne =>
		return "("+ee.p0.text()+" != "+ee.p1.text()+")";
	Param =>
		return ee.s;
	Str =>
		return "\""+ee.s+"\"";
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
	Normalise =>
		return sprint("normalise %s", ff.s);
	Lump =>
		return sprint("lump %s %s \"%s\"", ff.s, ff.cutoff, ff.str);
	}
}

has(s: string, l: list of string): int
{
	for(; l != nil; l = tl l)
		if(hd l == s)
			return 1;
	return 0;
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
