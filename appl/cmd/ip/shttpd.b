implement Shttpd;

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
include "env.m";
	env: Env;
include "string.m";
	str: String;
include "keyring.m";
	keyring: Keyring;
include "security.m";
	random: Random;
include "encoding.m";
	base64: Encoding;
include "sh.m";
	sh: Sh;
include "ip.m";
	ipm: IP;
	IPaddr: import ipm;
include "attrdb.m";
	attrdb: Attrdb;
	Db, Dbentry, Tuples: import attrdb;
include "regex.m";
	regex: Regex;
include "mhttp.m";
	http: Http;
	Url, Req, Resp, Hdrs, HTTP_10, HTTP_11, encodepath: import http;
	UNKNOWN, OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT: import http;

Version: con "shttpd/0";


Repl: adt {
	re:	regex->Re;
	rule:	list of ref (string, int);	# literal string, replacement group for regex
	maxrepl:	int;	# highest replacement group

	parse:	fn(restr, rulestr: string): (ref Repl, string);
	apply:	fn(r: self ref Repl, s: string): (int, string, string);
};

# config for a single host,port
Cfg: adt {
	host, port:	string;
	listings:	array of ref (string, int);  # path prefix, list (true/false)
	cachesecs:	int;
	listens:	list of ref (string, string);	# ip, port
	cgipaths:	list of ref (string, string, list of string, int);	# path, cmd|addr, methods, Cgi|Scgi
	indexfiles:	list of string;
	redirs:	list of ref Repl;
	auths:	list of ref (string, string, string);	# path, realm, base64 user:pass
	gzpaths:	list of string;

	new:	fn(): ref Cfg;
	read:	fn(e: ref Dbentry, defaultport: string): (ref Cfg, string);
	rev:	fn(cfg: self ref Cfg);
};

# config file, holds one Cfg per host,port
Cfgs: adt {
	file:	string;
	db:	ref Db;
	default:	ref Cfg;
	cfgs:	list of (string, string, ref Cfg);	# host, port (for lookup) => config

	accessfd:	ref Sys->FD;
	debugflag, vhostflag:	int;
	addrs:	list of string;
	usertypes:	list of ref (string, string);

	init:	fn(file: string): (ref Cfgs, string);
	read:	fn(file: string, db: ref Db): (ref Cfgs, string);
	find:	fn(c: self ref Cfgs, host, port: string): ref Cfg;
};

# represents a connection and a request on it
Op: adt {
	id:	int;	# connection id, for logging
	now:	int;	# time of start
	keepalive:	int;
	chunked:	int;
	length:		big;
	fd:	ref Sys->FD;
	inb:	ref Bufio->Iobuf;
	rhost, rport, lhost, lport:	string;
	req:	ref Req;
	resp:	ref Resp;
	cfgs:	ref Cfgs;
	cfg:	ref Cfg;
};

Cgitimeoutsecs: con 3*60;
Keepalivesecs: con 3*60;
defaddr: con "net!*!http";

debugflag: int;

webroot: string;
credempty: string;
ctlchan := "";

environment: list of (string, string);

Shttpd: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};

mimetypes := array[] of {
	(".pdf",	"application/pdf"),
	(".html",	"text/html; charset=utf-8"),
	(".htm",	"text/html; charset=utf-8"),
	(".txt",	"text/plain; charset=utf-8"),
	(".diff",	"text/plain; charset=utf-8"),
	(".patch",	"text/plain; charset=utf-8"),
	(".ps",		"application/postscript"),
	(".eps",	"application/postscript"),
	(".torrent",	"application/x-bittorrent"),
	(".dvi",	"application/x-dvi"),
	(".tar.gz",	"application/x-tgz"),
	(".tgz",	"application/x-tgz"),
	(".gz",		"application/x-gzip"),
	(".tar",	"application/x-tar"),
	(".mp3",	"audio/mpeg"),
	(".ogg",	"application/ogg"),
	(".jpg",	"image/jpeg"),
	(".gif",	"image/gif"),
	(".png",	"image/png"),
	(".css",	"text/css"),
	(".js",		"text/javascript; charset=utf-8"),
	(".c",		"text/plain; charset=utf-8"),
	(".b",		"text/plain; charset=utf-8"),
	(".h",		"text/plain; charset=utf-8"),
	(".y",		"text/plain; charset=utf-8"),
	(".sh",		"text/plain; charset=utf-8"),
	(".orig",	"text/plain; charset=utf-8"),
	(".conf",	"text/plain; charset=utf-8"),
	(".avi",	"video/x-msvideo"),
	(".bz2",	"application/x-bzip"),
	(".tex",	"text/plain; charset=utf-8"),
	(".mp4",	"video/mp4"),
	(".mpg",	"video/mpeg"),
	(".mpeg",	"video/mpeg"),
	(".ms",		"text/plain; charset=utf-8"),
	(".roff",	"text/plain; charset=utf-8"),
	(".man",	"text/plain; charset=utf-8"),
	(".me",		"text/plain; charset=utf-8"),
	(".t",		"text/plain; charset=utf-8"),
	(".tif",	"image/tiff"),
	(".tiff",	"image/tiff"),
	(".doc",	"application/msword"),
	(".ico",	"image/x-icon"),
	(".bmp",	"image/bmp"),
	(".tex",	"text/plain; charset=utf-8"),
	(".xls",	"application/vnd.ms-excel"),
	(".ppt",	"application/vnd.ms-powerpoint"),
	(".tar.bz2",	"application/x-bzip-compressed-tar"),
	(".bz2",	"application/x-bzip"),
	(".tbz",	"application/x-bzip-compressed-tar"),
	(".zip",	"application/zip"),
	(".wav",	"audio/x-wav"),
	(".jpeg",	"image/jpeg"),
	(".py",		"text/plain; charset=utf-8"),
};

Eok:			con 200;
Epartialcontent:	con 206;
Emovedpermanently:	con 301;
Enotmodified:		con 304;
Ebadrequest:		con 400;
Eunauthorized:		con 401;
Eforbidden:		con 403;
Enotfound:		con 404;
Emethodnotallowed:	con 405;
Elengthrequired:	con 411;
Epreconditionfailed:	con 412;
Ebadmediatype:		con 415;
Enotsatisfiable:	con 416;
Eexpectationfailed:	con 417;
Eservererror:		con 500;
Enotimplemented:	con 501;
Ebadversion:		con 505;

statusmsgs := array[] of {
	(100,		"Continue"),
	(200,		"OK"),
	(206,		"Partial Content"),
	(301,		"Moved Permanently"),
	(304,		"Not Modified"),
	(400,		"Bad Request"),
	(401,		"Unauthorized"),
	(403,		"Forbidden"),
	(404,		"Object Not Found"),
	(405,		"Method Not Allowed"),
	(411,		"Length Required"),
	(412,		"Precondition Failed"),
	(415,		"Unsupported Media Type"),
	(416,		"Requested Range Not Satisfiable"),
	(417,		"Expectation Failed"),
	(500,		"Internal Server Error"),
	(501,		"Not Implemented"),
	(505,		"HTTP Version Not Supported"),
};

# relevant known request headers whose values are not allowed to be concatenated (not a bnf #-rule, see rfc2616#2.1)
nomergeheaders := array[] of {
	# these two would be useful to merge.  alas, it is not allowed by rfc2616, section 4.2, last paragraph
	"if-match",
	"if-none-match",

	"authorization",
	"content-length",
	"content-type",
	"host",
	"if-modified-since",
	"if-range",
	"if-unmodified-since",
	"range",
};

idch: chan of int;
randch: chan of int;
killch: chan of int;
killschedch: chan of (int, int, chan of int);
excch: chan of (int, chan of string);
warnch: chan of (int, string);
cfgsgetch: chan of chan of ref Cfgs;
newcfgsch: chan of ref Cfgs;
logch: chan of (string, string);
logfdch: chan of ref Sys->FD;

timefd: ref Sys->FD;
errorfd: ref Sys->FD;

Cgi, Scgi: con iota;
cgitypes := array[] of {"cgi", "scgi"};

cgispawnch: chan of (string, string, string, ref Op, big, chan of (ref Sys->FD, ref Sys->FD, string));
scgidialch: chan of (string, chan of (ref Sys->FD, string));

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	bufio = load Bufio Bufio->PATH;
	env = load Env Env->PATH;
	daytime = load Daytime Daytime->PATH;
	keyring = load Keyring Keyring->PATH;
	random = load Random Random->PATH;
	str = load String String->PATH;
	base64 = load Encoding Encoding->BASE64PATH;
	sh = load Sh Sh->PATH;
	ipm = load IP IP->PATH;
	ipm->init();
	attrdb = load Attrdb Attrdb->PATH;
	err := attrdb->init();
	if(err != nil)
		fail("loading attrdb: "+err);
	regex = load Regex Regex->PATH;
	http = load Http Http->PATH;
	http->init(bufio);

	cfgs: ref Cfgs;

	(cfgs, err) = Cfgs.init("/dev/null");
	if(err != nil)
		fail("making empty config: "+err);
	defcfg := cfgs.default;

	arg := load Arg Arg->PATH;
	arg->init(args);
	arg->setusage(arg->progname()+" [-dh] [-A path realm user:pass] [-C cachesecs] [-L listpath 0|1] [-a addr] [-c path command methods] [-f ctlchan] [-i indexfile] [-l logfile] [-n config] [-r pathre dest] [-s path addr methods] [-t extension mimetype] [-z gzippath] webroot");
	while((c := arg->opt()) != 0)
		case c {
		'A' =>	defcfg.auths = ref (arg->earg(), arg->earg(), base64->enc(array of byte arg->earg()))::defcfg.auths;
			if(haschar((hd defcfg.auths).t1, '"')) {
				fprint(fildes(2), "realm must not have double quote, not supported by http/1.0");
				raise "fail:usage";
			}
		'C' =>	defcfg.cachesecs = int arg->earg();
		'L' =>	path := arg->earg();
			what := int arg->earg();
			nl := array[len defcfg.listings+1] of ref (string, int);
			nl[:] = defcfg.listings;
			nl[len defcfg.listings] = ref (path, what);
			defcfg.listings = nl;
		'a' =>	cfgs.addrs = arg->earg()::cfgs.addrs;
		'c' =>	defcfg.cgipaths = ref (arg->earg(), arg->earg(), sys->tokenize(arg->earg(), " ,").t1, Cgi)::defcfg.cgipaths;
		'd' =>	cfgs.debugflag++;
		'f' =>	ctlchan = arg->earg();
		'h' =>	cfgs.vhostflag++;
		'i' =>	defcfg.indexfiles = arg->earg()::defcfg.indexfiles;
		'l' =>	logfile := arg->earg();
			cfgs.accessfd = sys->open(logfile, Sys->OWRITE);
			if(cfgs.accessfd == nil)
				fail(sprint("open logfile %q: %r", logfile));
			sys->seek(cfgs.accessfd, big 0, Sys->SEEKEND);

		'n' =>
			file := arg->earg();
			(cfgs, err) = Cfgs.init(file);
			if(err != nil) {
				fprint(fildes(2), "reading %q: %s\n", file, err);
				raise "fail:usage";
			}
			defcfg = cfgs.default;
			defcfg.rev();
			cfgs.usertypes = rev(cfgs.usertypes);
			cfgs.addrs = rev(cfgs.addrs);
		'r' =>
			(restr, rulestr) := (arg->earg(), arg->earg());
			(repl, rerr) := Repl.parse(restr, rulestr);
			if(err != nil) {
				fprint(fildes(2), "parsing redir %q %q: %s\n", restr, rulestr, rerr);
				raise "fail:usage";
			}
			defcfg.redirs = repl::defcfg.redirs;
		's' =>	defcfg.cgipaths = ref (arg->earg(), arg->earg(), sys->tokenize(arg->earg(), " ,").t1, Scgi)::defcfg.cgipaths;
		't' =>	cfgs.usertypes = ref (arg->earg(), arg->earg())::cfgs.usertypes;
		'z' =>	defcfg.gzpaths = arg->earg()::defcfg.gzpaths;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1)
		arg->usage();
	webroot = hd args;
	defcfg.rev();
	cfgs.usertypes = rev(cfgs.usertypes);
	cfgs.addrs = rev(cfgs.addrs);
	credempty = base64->enc(array of byte ":");	# empty-user:empty-pass

	environment = env->getall();

	pid := sys->pctl(Sys->NEWPGRP|Sys->FORKNS|Sys->FORKENV|Sys->FORKFD, nil);
	if(pid < 0)
		fail(sprint("pctl: %r"));
	if(sys->chdir(webroot) != 0)
		fail(sprint("chdir webroot %q: %r", webroot));

	if(ctlchan != nil) {
		fio := sys->file2chan("/chan", ctlchan);
		if(fio == nil)
			fail(sprint("file2chan in /chan: %q: %r", ctlchan));
		spawn ctlhandler(fio);
	}

	timefd = sys->open("/dev/time", Sys->OREAD);
	if(timefd == nil)
		fail(sprint("open /dev/time: %r"));

	errorfd = sys->open("/services/logs/shttpderror", Sys->OWRITE);
	if(errorfd != nil)
		sys->seek(errorfd, big 0, Sys->SEEKEND);

	idch = chan[8] of int;
	spawn idgen();
	randch = chan of int;
	spawn randgen();
	killch = chan of int;
	killschedch = chan of (int, int, chan of int);
	spawn killer();
	excch = chan of (int, chan of string);
	spawn exceptsetter();
	warnch = chan of (int, string);
	spawn warner();

	cfgsgetch = chan of chan of ref Cfgs;
	newcfgsch = chan of ref Cfgs;
	spawn cfgsserver();

	logch = chan of (string, string);
	logfdch = chan of ref Sys->FD;
	spawn logger();

	newcfgsch <-= cfgs;

	cgispawnch = chan of (string, string, string, ref Op, big, chan of (ref Sys->FD, ref Sys->FD, string));
	spawn cgispawner();

	scgidialch = chan of (string, chan of (ref Sys->FD, string));
	spawn scgidialer();

	if(cfgs.addrs == nil)
		cfgs.addrs = defaddr::nil;
	for(addrs := rev(cfgs.addrs); addrs != nil; addrs = tl addrs) {
		addr := hd addrs;
		(aok, aconn) := sys->announce(addr);
		if(aok != 0)
			fail(sprint("announce %q: %r", addr));
		spawn listen(hd addrs, aconn, sync := chan of int);
		<-sync;
	}
	warn(0, sprint("shttpd started at %s", daytime->time()));
}

listen(addr: string, aconn: Sys->Connection, sync: chan of int)
{
	sync <-= 0;
	for(;;) {
		(lok, lconn) := sys->listen(aconn);
		if(lok != 0)
			fail(sprint("listen %q: %r", addr));
		dfd := sys->open(lconn.dir+"/data", Sys->ORDWR);
		if(dfd != nil)
			spawn httpserve(dfd, lconn.dir);
		else
			warn(0, sprint("open connection file: %r"));
		lconn.dfd = nil;
	}
}

idgen()
{
	id := 1;
	for(;;)
		idch <-= id++;
}

randgen()
{
	for(;;)
		randch <-= random->randomint(Random->NotQuiteRandom);
}

killer()
{
	for(;;) alt {
	pid := <-killch =>
		kill(pid);
	(pid, timeout, respch) := <-killschedch =>
		spawn timeoutkill(pid, timeout, respch);
	}
}

cfgsserver()
{
	cfgs: ref Cfgs;

	for(;;) alt {
	respch := <-cfgsgetch =>
		respch <-= cfgs;
	cfgs = <-newcfgsch =>
		# non-atomic wrt other threads...  not much to do about it
		debugflag = cfgs.debugflag;
		logfdch <-= cfgs.accessfd;
	}
}

timeoutkill(pid, timeout: int, respch: chan of int)
{
	respch <-= sys->pctl(0, nil);
	sys->sleep(timeout);
	kill(pid);
}

exceptsetter()
{
	for(;;) {
		(pid, respch) := <-excch;
		err: string;
		fd := sys->open(sprint("/prog/%d/ctl", pid), Sys->OWRITE);
		if(fd == nil || fprint(fd, "exceptions notifyleader") == -1)
			err = sprint("setting exception handling for pid %d: %r", pid);
		if(respch == nil && err != nil) {
			warn(0, sprint("setting exceptions notifyleader for pid %d: %s", pid, err));
			kill(pid);
		}
		if(respch != nil)
			respch <-= err;
	}
}

warner()
{
	for(;;) {
		(id, s) := <-warnch;
		if(s != nil && s[len s-1] == '\n')
			s = s[:len s-1];
		warn(id, s);
	}
}

cgispawner()
{
	for(;;) {
		(cmd, path, cgipath, op, length, replych) := <-cgispawnch;
		spawn cgispawn(cmd, path, cgipath, op, length, replych);
	}
}

cgispawn(cmd, path, cgipath: string, op: ref Op, length: big, replych: chan of (ref Sys->FD, ref Sys->FD, string))
{
	p0 := array[2] of ref Sys->FD;
	p1 := array[2] of ref Sys->FD;
	p2 := array[2] of ref Sys->FD;
	if(sys->pipe(p0) != 0 || sys->pipe(p1) != 0 || sys->pipe(p2) != 0) {
		replych <-= (nil, nil, sprint("pipe: %r"));
		return;
	}

	spawn errlogger(op, p2[0]);

	if(sys->pctl(Sys->NEWPGRP|Sys->NEWFD|Sys->FORKNS|Sys->FORKENV, p0[0].fd::p1[0].fd::p0[1].fd::p1[1].fd::p2[1].fd::nil) < 0) {
		replych <-= (nil, nil, sprint("pctl newpgrp,newfd,forkns,forkenv: %r"));
		return;
	}

	for(l := cgivars(path, cgipath, op, length, nil); l != nil; l = tl l) {
		epath := "/env/"+(hd l).t0;
		efd := sys->create(epath, Sys->OWRITE, 8r666);
		if(efd == nil) {
			replych <-= (nil, nil, sprint("open %q: %r", epath));
			return;
		}
		d := array of byte (hd l).t1;
		if(sys->write(efd, d, len d) != len d) {
			replych <-= (nil, nil, sprint("write %q: %r", epath));
			return;
		}
	}

	if(sys->dup(p0[1].fd, 0) == -1 || sys->dup(p1[1].fd, 1) == -1 || sys->dup(p2[1].fd, 2) == -1) {
		replych <-= (nil, nil, sprint("dup: %r"));
		return;
	}

	replych <-= (p0[0], p1[0], nil);

	p0[1] = fildes(p0[1].fd);
	p1[1] = fildes(p1[1].fd);
	p2[1] = fildes(p2[1].fd);
	p0[0] = p1[0] = p2[0] = nil;

	err := sh->system(nil, cmd);
	if(err != nil)
		warnch <-= (op.id, sprint("cgispawn, command %q: %s", cmd, err));
}

errlogger(op: ref Op, fd: ref Sys->FD)
{
	for(;;) {
		n := sys->read(fd, d := array[Sys->ATOMICIO] of byte, len d);
		if(n < 0)
			warnch <-= (op.id, sprint("reading stderr: %r"));
		if(n <= 0)
			break;
		warnch <-= (op.id, string d[:n]);
	}
}

scgidialer()
{
	for(;;) {
		(scgiaddr, replychan) := <-scgidialch;
		spawn scgidial(scgiaddr, replychan);
	}
}

scgidial(scgiaddr: string, replychan: chan of (ref Sys->FD, string))
{
	(ok, conn) := sys->dial(scgiaddr, nil);
	if(ok < 0)
		replychan <-= (nil, sprint("dialing scgid %q: %r", scgiaddr));
	else
		replychan <-= (conn.dfd, nil);
}

ctlhandler(fio: ref Sys->FileIO)
{
	for(;;) alt {
	(nil, nil, nil, rc) := <- fio.read =>
		if(rc == nil)
			continue;
		rc <-= (nil, "permission denied");

        (nil, data, nil, wc) := <- fio.write =>
                if(wc == nil)
                        continue;
		s := string data;
		if(s != nil && s[len s-1] == '\n')
			s = s[:len s-1];
		case s {
		"reload" =>
			cfgsgetch <-= respch := chan of ref Cfgs;
			cfgs := <-respch;

			if(cfgs.db.reopen() != 0) {
				msg := sprint("reopening config file: %r");
				warn(0, msg);
				wc <-= (0, msg);
				continue;
			}
			(ncfgs, err) := Cfgs.read(cfgs.file, cfgs.db);
			if(err != nil) {
				msg := "error reloading config, keeping current: "+err;
				warn(0, msg);
				wc <-= (0, msg);
				continue;
			}
			newcfgsch <-= ncfgs;
			warn(0, "config file reloaded");
			wc <-= (len data, nil);
		* =>
			wc <-= (0, sprint("bad command: %q", s));
		}
	}
}

httpserve(fd: ref Sys->FD, conndir: string)
{
	id := <-idch;
	if(debugflag) say(id, "httpserve");

	(lhost, lport) := readaddr(id, conndir+"/local");
	(rhost, rport) := readaddr(id, conndir+"/remote");
	lhost = IPaddr.parse(lhost).t1.text();
	rhost = IPaddr.parse(rhost).t1.text();
	if(debugflag) say(id, sprint("connect from %s:%s to %s:%s", rhost, rport, lhost, lport));

	pid := sys->pctl(Sys->NEWPGRP|Sys->FORKNS|Sys->NODEVS, nil);
	if(pid < 0)
		die(id, sprint("pctl: %r"));
	excch <-= (pid, nil);
	if(sys->bind(webroot,  "/", Sys->MREPL) < 0)
		die(id, sprint("bind %q /: %r", webroot));

	b := bufio->fopen(fd, Bufio->OREAD);
	if(b == nil)
		die(id, sprint("bufio open: %r"));

	op := ref Op(id, 0, 0, 0, big 0, fd, b, rhost, rport, lhost, lport, nil, nil, nil, nil);

	for(nsrvs := 0; ; nsrvs++) {
		if(nsrvs > 0 && !op.keepalive)
			break;

		if(sys->chdir("/") != 0)
			break;

		op.chunked = op.keepalive = 0;
		op.length = big -1;
		op.req = nil;
		op.resp = nil;
		op.cfgs = nil;
		op.cfg = nil;
		httptransact(pid, b, op);
	}
}

httptransact(pid: int, b: ref Iobuf, op: ref Op)
{
	id := op.id;
	op.now = readtime();
	hdrs := Hdrs.new(("server", Version)::nil);

	# kill ourselve when no request comes in
	killschedch <-= (pid, Keepalivesecs*1000, respch := chan of int);
	killpid := <-respch;

	(req, rerr) := Req.read(b);
	cfgsgetch <-= cfgsrespch := chan of ref Cfgs;
	op.cfgs = <-cfgsrespch;

	hdrs.add("date", httpdate(op.now));
	if(rerr != nil || req.major != 1 || req.method == UNKNOWN) {
		st := Ebadrequest;
		if(rerr == nil && req.major != 1) {
			st = Ebadversion;
			rerr = sprint("Version requested is HTTP/%d.%d", req.major, req.minor);
		} else if(rerr == nil && req.method == UNKNOWN) {
			st = Enotimplemented;
			rerr = sprint("Method %q not supported", req.methodstr);
		}

		stmsg := statusmsg(st);
		op.resp = Resp.mk(HTTP_10, string st, stmsg, hdrs);

		html := array of byte mkhtml(sprint("%d - %s: %s", st, stmsg, rerr));

		op.resp.h.add("content-type", "text/html; charset=utf-8");
		op.resp.h.add("content-length", string len html);

		err := hresp(op.resp, op.fd, 0, 0);
		if(err == nil)
			sys->write(op.fd, html, len html);

		killch <-= killpid;
		die(id, "reading request: "+rerr);
	}
	killch <-= killpid;
	if(debugflag) say(id, sprint("request: method %q url %q version %q",
		req.methodstr, req.url.pack(), sprint("HTTP/%d.%d", req.major, req.minor)));
	op.req = req;

	# all values besides "close" are supposedly header names, not important
	(contoks, conerr) := tokenize(req.h.getlist("connection"));
	if(conerr != nil || len contoks == 0 && req.h.has("connection", nil))
		return responderrmsg(op, Ebadrequest, sprint("Bad Request: Bad value for header \"Connection\""));

	op.keepalive = req.version() >= HTTP_11 && conerr == nil && !listhas(contoks, "close");
	op.resp = resp := Resp.mk(req.version(), "200", "OK", hdrs);

	# tell client if it is sending ambiguous requests: duplicate headers of the important kind
	for(i := 0; i < len nomergeheaders; i++)
		if(len req.h.findall(nomergeheaders[i]) > 1)
			return responderrmsg(op, Ebadrequest, sprint("Bad Request: Duplicate headers:  \"%s\"", nomergeheaders[i]));

	if(req.h.has("proxy-authorization", nil))
		return responderrmsg(op, Ebadrequest, "Bad Request: Proxy-Authorization credentials sent, unacceptable");

	if(req.version() >= HTTP_11 && !req.h.has("host", nil))
		return responderrmsg(op, Ebadrequest, "Bad Request: Missing header \"Host\"");

	# when host-header is absent, we'll request the empty host name, the default
	host := splithost(req.h.get("host")).t0;
	if(str->drop(host, "0-9a-zA-Z.:-") != nil || str->splitstrl(host, "..").t1 != nil)
		return responderrmsg(op, Ebadrequest, nil);

	cfg := op.cfg = op.cfgs.find(host, op.lport);
	if(cfg == nil)
		return responderrmsg(op, Enotfound, nil);

	# do not accept request when doing vhost and request is from ip that we shouldn't serve host:port on
	if(op.cfgs.vhostflag && cfg.listens != nil) {
		addrokay := 0;
		for(ls := cfg.listens; !addrokay && ls != nil; ls = tl ls) {
			(chost, cport) := *(hd ls);
			addrokay = chost == op.lhost && cport == op.lport;
		}
		if(!addrokay) {
			say(id, "request on ip:port, not allowed");
			return responderrmsg(op, Enotfound, nil);
		}
	}

	if(req.version() == HTTP_10 && req.method != GET && req.method != HEAD && req.method != POST)
		return responderrmsg(op, Enotimplemented, sprint("Unknown Method: \"%s\"", req.methodstr));

	if(hasbody(op.req) && (req.method == GET || req.method == HEAD || req.method == TRACE || req.method == DELETE)) {
		op.keepalive = 0;
		return responderrmsg(op, Ebadrequest, "Bad Request: Entity not allowed in request");
	}
	# for other methods, we ignore bodies by closing the connection.  saner than reading and discarding...

	case req.method {
	GET or HEAD =>
		;
	POST =>
		if(hasbody(op.req))
			op.keepalive = 0;
	TRACE =>
		# bug: the response does not have * as path, but /
		return respond(op, Eok, req.pack(), "message/http");

	OPTIONS =>
		# only (s)cgi paths allow POST, but we won't say, the path may require auth as well.  what to do then?
		hdrs.add("allow", "OPTIONS, GET, HEAD, POST, TRACE");
		hdrs.add("accept-ranges", "bytes");
		if(hasbody(op.req))
			op.keepalive = 0;
		return responderrmsg(op, Eok, nil);

	PUT or DELETE =>
		# note: when implementing these, complete support for if-match and if-none-match, and much more probably
		if(hasbody(op.req))
			op.keepalive = 0;
		return responderrmsg(op, Enotimplemented, "Not Implemented: PUT and DELETE are not supported");

	* =>
		if(hasbody(op.req))
			op.keepalive = 0;
		return responderrmsg(op, Enotimplemented, sprint("Unknown Method: \"%s\"", req.methodstr));
	}

	# remove occurrences of "/elem/../" from path, returned path always starts with "/"
	path := pathsanitize(req.url.path);

	# we ignore the port in the host-header.  this is illegal according to rfc2616, but using it is just silly.
	# also, we violate rfc2616 by sending 404 "not found" when the host doesn't exist.
	# we should send 400 "bad request" then, but that is just silly too.
	if(op.cfgs.vhostflag) {
		hostdir: string;
		if(cfg.host != "") {
			hostdir = cfg.host+"!"+cfg.port;
			if(sys->chdir(hostdir) != 0) {
				if(debugflag) say(id, sprint("using hostdir %q from config failed, trying default", hostdir));
				hostdir = nil;
			}
		}
		if(hostdir == nil) {
			hostdir = "_default!"+cfg.port;
			if(sys->chdir(hostdir) != 0)
				return responderrmsg(op, Enotfound, nil);
		}
		if(debugflag) say(id, sprint("using hostdir %q, path %q", hostdir, path));
	}

	validauth := needauth := 0;
	realm: string;
	authtype, cred: string;
	(authtype, cred) = str->splitstrr(req.h.get("authorization"), " ");
	if(str->tolower(authtype) != "basic ")
		cred = nil;
	else
		cred = stripws(cred);
	for(a := cfg.auths; !validauth && a != nil; a = tl a) {
		(apath, arealm, acred) := *hd a;
		if(str->prefix(apath, path)) {
			needauth = 1;
			realm = arealm;
			validauth = cred == acred;
		}
	}
	if(needauth && !validauth) {
		resp.h.add("www-authenticate", sprint("Basic realm=\"%s\"", realm));
		return responderrmsg(op, Eunauthorized, nil);
	}
	if(req.h.has("authorization", nil) && !needauth && cred != credempty) {
		resp.h.add("www-authenticate", sprint("Basic realm=\"authentication not allowed, use empty username/password\""));
		return responderrmsg(op, Eunauthorized, "Not Authorized:  Sending authorization credentials is not allowed for "+
			"this resource.  Please use an empty username and password or do not send authorization credentials altogether.");
	}
	if(debugflag && validauth) say(id, "have valid auth credentials");

	for(r := cfg.redirs; r != nil; r = tl r) {
		repl := hd r;
		(match, dest, replerr) := repl.apply(path);
		if(replerr != nil) {
			warn(id, "redirections misconfiguration: "+replerr);
			return responderrmsg(op, Eservererror, "Internal Server Error: An error occurred while handling a redirection");
		}
		if(!match)
			continue;
		if(!str->prefix("http://", dest) && !str->prefix("https://", dest)) {
			(havehost, hosthdr) := req.h.find("host");
			if(havehost) {
				dest = "http://"+hosthdr+dest;
			} else {
				lport := "";
				if(op.lport != "80")
					lport = ":"+op.lport;
				httphost := op.lhost;
				(ok, ip) := IPaddr.parse(httphost);
				if(ok == 0 && !ip.isv4())
					httphost = "["+httphost+"]";
				dest = "http://"+httphost+lport+dest;
			}
		}
		if(debugflag) say(id, sprint("redirecting from %q to %q", path, dest));
		resp.h.set("location", dest);
		dest = htmlescape(dest);
		st := Emovedpermanently;
		html := mkhtmlstart(sprint("%d - %s", st, statusmsg(st))) +
			sprint("<h1>Moved Permanently: Moved to <a href=\"%s\">%s</a></h1>\n", dest, dest)+"</body></html>\n";
		return respond(op, Emovedpermanently, html, "text/html; charset=utf-8");
	}

	if(((cgipath, cgiaction, methods, cgitype) := findcgi(cfg, path)).t1 != nil) {
		if(methods != nil && !hasmethod(methods, req.methodstr))
			return responderrmsg(op, Emethodnotallowed, nil);
		return cgi(path, op, cgipath, cgiaction, cgitype);
	}

	# path is one of:  plain file, directory (either listing or plain index file)
	dfd := sys->open("."+path, Sys->OREAD);
	if(dfd != nil)
		(dok, dir) := sys->fstat(dfd);
	if(dok == 0 && dir.mode&Sys->DMDIR && path[len path-1] == '/') {
		for(l := cfg.indexfiles; l != nil; l = tl l) {
			ipath := "."+path+hd l;
			(iok, idir) := sys->stat(ipath);
			if(iok != 0 || idir.mode&Sys->DMDIR)
				continue;
			ifd := sys->open(ipath, Sys->OREAD);
			if(ifd == nil)
				return responderrmsg(op, Enotfound, nil);
			if(debugflag) say(id, sprint("using index file %q", hd l));
			dfd = ifd;
			dir = idir;
			path += hd l;
			break;
		}
	}
	if(dfd == nil || dok != 0 || (dir.mode&Sys->DMDIR) && (!dolisting(cfg, path) || path != nil && path[len path-1] != '/'))
		return responderrmsg(op, Enotfound, nil);

	if(req.method == POST) {
		resp.h.add("allow", "GET, HEAD, OPTIONS");
		return responderrmsg(op, Emethodnotallowed, "Method Not Allowed: POST not allowed");
	}

	resp.h.add("last-modified", httpdate(dir.mtime));
	tag := etag(path, op, dir);
	resp.h.add("etag", tag);

	ifmatch, ifnonematch, ifunmodsincestr: string;
	havecond: int;
	(havecond, ifmatch) = req.h.find("if-match");
	if(req.version() >= HTTP_11 && havecond && !etagmatch(req.version(), tag, ifmatch, 1))
		return responderrmsg(op, Epreconditionfailed, sprint("Precondition Failed: Etag(s) \"%s\", specified with If-Match did not match", ifmatch));

	ifmodsince := parsehttpdate(req.h.get("if-modified-since"));
	# http/1.0, head and if-modified-since: rfc1945#8.1;  unsupported date value can safely be ignored.
	if(!(req.version() == HTTP_10 && req.method == HEAD) && ifmodsince && dir.mtime <= ifmodsince)
		return responderr(op, Enotmodified);

	# note: for get this is okay, but for put/delete a bad-syntax value would be have to raise an error
	(havecond, ifnonematch) = req.h.find("if-none-match");
	if(req.version() >= HTTP_11 && havecond && req.method == GET && etagmatch(req.version(), tag, ifnonematch, 0))
		return responderr(op, Enotmodified);

	# unsupported date value causes a "precondition failed"
	(havecond, ifunmodsincestr) = req.h.find("if-unmodified-since");
	ifunmodsince := parsehttpdate(ifunmodsincestr);
	if(req.version() >= HTTP_11 && (ifunmodsince && dir.mtime > ifunmodsince || havecond && ifunmodsince == 0))
		return responderrmsg(op, Epreconditionfailed, sprint("Precondition Failed: Object has been modified since \"%s\"", req.h.get("if-unmodified-since")));

	if(dir.mode&Sys->DMDIR)
		listdir(path, op, dfd);
	else
		plainfile(path, op, dfd, dir, tag);
}

pathsanitize(path: string): string
{
	trailslash := path != nil && path[len path-1] == '/';

	(nil, elems) := sys->tokenize(path, "/");
	r: list of string;
	for(; elems != nil; elems = tl elems)
		if(hd elems == ".")
			continue;
		else if(hd elems == "..") {
			if(r != nil)
				r = tl r;
		} else
			r = hd elems::r;
	s := "";	
	for(; r != nil; r = tl r)
		s = "/"+hd r+s;
	if(trailslash || s == "")
		s += "/";
	return s;
}

findcgi(cfg: ref Cfg, path: string): (string, string, list of string, int)
{
	for(l := cfg.cgipaths; l != nil; l = tl l)
		if(str->prefix((*hd l).t0, path))
			return *hd l;
	return (nil, nil, nil, 0);
}

etag(path: string, op: ref Op, dir: Sys->Dir): string
{
	host := splithost(op.req.h.get("host")).t0;
	if(host == nil)
		host = "_default";
	return "\""+sha1(array of byte sprint("%d,%d,%s,%s,%s", dir.qid.vers, dir.mtime, host, op.lport, path))+"\"";
}

etagmatch(version: int, etag: string, etagstr: string, strong: int): int
{
	if(etagstr == "*")
		return 1;
	(l, err) := tokenizeqs(etagstr, version);
	if(err != nil)
		return 0;
	for(; l != nil; l = tl l)
		if(hd l == etag && (!strong || !str->prefix("W/", hd l)))
			return 1;
	return 0;
}

plainfile(path: string, op: ref Op, dfd: ref Sys->FD, dir: Sys->Dir, tag: string)
{
	id := op.id;
	req := op.req;
	resp := op.resp;

	if(debugflag) say(id, "doing plain file");
	ct := mimetype(op.cfgs, path);
	if(ct != nil)
		resp.h.add("content-type", ct);
	else
		warn(op.id, sprint("could not determine content-type:  host %q path %q query %q", op.req.h.get("host"), op.req.url.path, op.req.url.query));

	# synthetic files sometimes don't have meaningful dir.length.
	# there is no one true way to determine if a file is synthetic.  this is the most reasonable.
	issynthetic := dir.length == big 0 && dir.qid.vers == 0;
	if(issynthetic) {
		op.chunked = resp.version() >= HTTP_11;
	} else {
		op.length = dir.length;
		resp.h.add("content-length", string op.length);
	}

	if(issynthetic && (req.h.has("range", nil) || req.h.has("if-range", nil)))
		return responderrmsg(op, Enotsatisfiable, nil);

	(valid, ranges) := parserange(req.version(), req.h.find("range"), dir.length);
	if(!valid) {
		resp.h.add("content-range", sprint("bytes */%bd", dir.length));
		return responderrmsg(op, Enotsatisfiable, nil);
	}
	bound := "";
	ifrange := req.h.get("if-range");
	# unsupported date value can safely be ignored.
	if(ranges != nil && (ifrange == nil
	                     || ifrange[0] == '"' && tag == ifrange
	                     || dir.mtime <= parsehttpdate(ifrange))) {
		if(len ranges == 1) {
			(start, end) := *hd ranges;
			resp.h.add("content-range", sprint("bytes %bd-%bd/%bd", start, end-big 1, dir.length));
			resp.h.set("content-length", string (end-start));
		} else {
			bound = sha1(array of byte (string <-randch+","+string op.now));
			resp.h.set("content-type", "multipart/byteranges; boundary="+bound);
			resp.h.del("content-length", nil);
			op.chunked = resp.version() >= HTTP_11;
		}
		resp.st = string Epartialcontent;
		resp.stmsg = "Partial Content";
		if(debugflag) say(id, sprint("sending %d ranges for multipart/byterange response", len ranges));
	} else
		ranges = ref (big 0, dir.length)::nil;

	if(gzipallowed(op.cfg.gzpaths, path))
	if(gzipaccepted(req.h))
	if(!issynthetic)
	if(!req.h.find("range").t0)
	if(!req.h.find("if-range").t0)
	if((gzfd := sys->open(gzpath := "."+path+".gz", sys->OREAD)) != nil)
	if(((nil, gzd) := sys->stat(gzpath)).t0 == 0)
	if(gzd.length < dir.length)
	if(gzd.mtime >= dir.mtime) {
		op.length = gzd.length;
		ranges = ref (big 0, gzd.length)::nil;
		resp.h.add("content-encoding", "gzip");
		resp.h.set("content-length", string gzd.length);
		dfd = gzfd;
		dir = gzd;
	}

	if(op.cfg.cachesecs >= 0)
		resp.h.add("cache-control", sprint("max-age=%d", op.cfg.cachesecs));

	accesslog(op);

	rerr := hresp(resp, op.fd, op.keepalive, op.chunked);
	if(rerr != nil)
		die(id, "writing response: "+rerr);

	if(req.method == HEAD)
		return;

	if(issynthetic) {
		buf := array[Sys->ATOMICIO] of byte;
		for(;;) {
			n := sys->readn(dfd, buf, len buf);
			if(n == 0)
				break;
			if(n < 0)
				die(id, sprint("reading file: %r"));
			hwrite(op, buf[:n]);
		}
		hwriteeof(op);
		return;
	}

	for(; ranges != nil; ranges = tl ranges) {
		(off, end) := *hd ranges;
		if(bound != nil) {
			s := sprint("--%s\r\ncontent-type: %s\r\ncontent-range: bytes %bd-%bd/%bd\r\n\r\n",
				bound, ct, off, end-big 1, dir.length);
			hwrite(op, array of byte s);
		}
		while(off < end) {
			want := end-off;
			if(want > big Sys->ATOMICIO)
				want = big Sys->ATOMICIO;
			n := sys->pread(dfd, d := array[int want] of byte, len d, off);
			if(n < 0)
				die(id, sprint("reading file: %r"));
			if(n == 0)
				break;
			off += big n;
			hwrite(op, d[:n]);
		}
		if(bound != nil)
			hwrite(op, array of byte "\r\n");
	}
	hwriteeof(op);
}

gzipallowed(l: list of string, p: string): int
{
	for(; l != nil; l = tl l)
		if(str->prefix(hd l, p))
			return 1;
	return 0;
}

# warning: parsing is simplistic, not handling full http rules, but should be good enough for finding "gzip".
gzipaccepted(h: ref Hdrs): int
{
	for(l := sys->tokenize(h.get("accept-encoding"), ",").t1; l != nil; l = tl l)
		if(strip(str->splitstrl(hd l, ";").t0, " \t") == "gzip")
			return 1;
	return 0;
}

dolisting(cfg: ref Cfg, path: string): int
{
	for(i := 0; i < len cfg.listings; i++) {
		(lpath, what) := *cfg.listings[i];
		if(str->prefix(lpath, path)) {
			say(-1, sprint("listing for path %q: %d, prefix: %q", path, what, lpath));
			return what;
		}
	}
	return 0;
}

listdir(path: string, op: ref Op, dfd: ref Sys->FD)
{
	id := op.id;
	req := op.req;
	resp := op.resp;

	if(debugflag) say(id, "doing directory listing");
	resp.h.add("content-type", "text/html; charset=utf-8");
	op.chunked = resp.version() >= HTTP_11;

	if(op.cfg.cachesecs >= 0)
		resp.h.add("cache-control", sprint("max-age=%d", op.cfg.cachesecs));

	accesslog(op);

	rerr := hresp(resp, op.fd, op.keepalive, op.chunked);
	if(rerr != nil)
		die(id, "writing response: "+rerr);

	if(req.method == HEAD)
		return;

	begin := mkhtmlstart("listing for "+path) + sprint("<h1>listing for %s</h1><hr/><table><tr><th>last modified</th><th>size</th><th>name</th></tr>\n", pathurls(path));
	hwrite(op, array of byte begin);
	for(;;) {
		(nd, d) := sys->dirread(dfd);
		if(nd < 0)
			die(id, sprint("reading dir: %r"));
		if(nd == 0)
			break;
		html := "";
		for(i := 0; i < nd && i < len d; i++) {
			name := d[i].name;
			if(d[i].mode & Sys->DMDIR)
				name += "/";
			html += sprint("<tr><td class=\"mtime\">%s</td><td class=\"size\">%bd</td><td class=\"name\"><a href=\"%s\">%s</a></td></tr>\n", daytime->filet(op.now, d[i].mtime), d[i].length, htmlescape(encodepath("./"+name)), htmlescape(name));
		}
		hwrite(op, array of byte html);
	}
	end := sprint("</table><hr/></body></html>\n");
	hwrite(op, array of byte end);
	hwriteeof(op);
}

mkhtmlstart(msg: string): string
{
	return sprint("<html><head>\n<style type=\"text/css\">\nh1 { font-size: 1.4em; }\ntd, th { padding-left: 1em; padding-right: 1em; }\ntd.mtime, td.size { text-align: right; }\n</style>\n<title>%s</title>\n</head><body>\n", htmlescape(msg));
}

mkhtml(msg: string): string
{
	return mkhtmlstart(msg)+sprint("\n<h1>%s</h1>\n</body></html>\n", htmlescape(msg));
}

htmlescape(s: string): string
{
	r := "";
	for(i := 0; i < len s; i++)
		case s[i] {
		'<' =>	r += "&lt;";
		'>' =>	r += "&gt;";
		'&' =>	r += "&amp;";
		'"' =>	r += "&quot;";
		* =>	r += s[i:i+1];
		}
	return r;
}

pathurls(s: string): string
{
	(nil, l) := sys->tokenize(s, "/");
	r := "";
	i := 0;
	path := "./";
	for(l = rev(l); l != nil; l = tl l) {
		r = sprint(" <a href=\"%s\">%s/</a>", path, htmlescape(hd l))+r;
		if(i == 0)
			path = "../";
		else
			path += "../";
		i += 1;
	}
	r = sprint("<a href=\"%s\">/</a>", path)+r;
	return r;
}

cgi(path: string, op: ref Op, cgipath, cgiaction: string, cgitype: int)
{
	id := op.id;
	req := op.req;

	if(debugflag) say(id, sprint("passing to (s)cgi handler, cgipath %q cgiaction %q", cgipath, cgiaction));

	# first, some sanity checks on the request
	# parsing/handling full transfer-coding is too involved for us.
	# we are taking a short cut here to avoid feeding the bloat monster.
	length := big 0;
	needcontinue := 0;
	if(req.method == POST) {
		transferenc := req.h.getlist("transfer-encoding");
		if(req.version() >= HTTP_11 && transferenc != nil && transferenc != "identity")
			return responderrmsg(op, Enotimplemented, "Not Implemented: Transfer-Encodings other than \"identity\" "+
				"(i.e. no transfer encoding) are not supported");

		if(req.h.has("content-length", nil)) {
			lengthstr := req.h.get("content-length");
			if(lengthstr == nil || str->drop(lengthstr, "0-9") != "")
				return responderrmsg(op, Ebadrequest,
					sprint("Bad Request: Invalid Content-Length: \"%s\"", lengthstr));
			length = big lengthstr;
		} else {
			(e, emsg) := (Elengthrequired, "");
			if(req.version() == HTTP_10) # rfc1945#7.2.2
				(e, emsg) = (Ebadrequest, "Bad Request: Missing header \"Content-Length\"");
			return responderrmsg(op, e, emsg);
		}

		contentenc := req.h.getlist("content-encoding");
		if(contentenc != nil && contentenc != "identity")
			return responderrmsg(op, Enotimplemented, "Not Implemented: Content-Encoding other than identity "+
				"(i.e. no content encoding) are not supported");

		needcontinue = req.version() >= HTTP_11 && req.h.has("expect", nil);
		if(needcontinue && (expect := str->tolower(req.h.getlist("expect"))) != "100-continue")
			return responderrmsg(op, Eexpectationfailed,
				sprint("Expectectation Failed: Unrecognized expectation:  %s", expect));

		if(debugflag) say(id, sprint("post, client content-length %bd", length));
	}

	timeo := Cgitimeoutsecs*1000;
	donech := chan of int;

	spawn timeout(op, timeo, timeoch := chan of int, donech);
	timeopid := <- timeoch;
	if(timeopid < 0)
		die(op.id, "timeout proc failed");
	spawn cgiproc(path, op, cgipath, cgiaction, cgitype, length, needcontinue, timeopid, timeoch, donech);

	# wait for timeout or cgiproc
	<-donech;
	return;
}

timeout(op: ref Op, timeo: int, timeoch, donech: chan of int)
{
	pid := sys->pctl(Sys->NEWPGRP, nil);
	timeoch <-= pid;
	if(pid < 0)
		return warn(op.id, sprint("pctl: %r"));
		
	opid := <-timeoch;
	sys->sleep(timeo);
	if(debugflag) say(op.id, sprint("timeout %d ms for request, killing handler pid %d, timeopid %d", timeo, opid, pid));
	killch <-= opid;
	responderrmsg(op, Eservererror, "Internal Server Error: Response could not be generated in time");
	donech <-= 0;
}

cgiproc(path: string, op: ref Op, cgipath, cgiaction: string, cgitype: int, length: big, needcontinue: int, timeopid: int, cgich, donech: chan of int)
{
	# set up new process group and exception propagation so
	# we always clean up nicely when one of the child procs dies.
	# we always have to respond on donech (or be killed by the timeout
	# proc) or we'll leave processes lingering
	err: string;
	npid := sys->pctl(Sys->NEWPGRP, nil);
	if(npid < 0)
		err = sprint("pctl newpgrp: %r");
	if(err == nil) {
		excch <-= (npid, respch := chan of string);
		err = <-respch;
	}

	if(err != nil) {
		killch <-= timeopid;
		warn(op.id, err);
		responderrmsg(op, Eservererror, nil);
		donech <-= 0;
		return;
	}

	# to make sure our caller can return (e.g. when writing to remote fails)
	{
		_cgiproc(path, op, cgipath, cgiaction, cgitype, length, needcontinue, timeopid, cgich);
	} exception {
	* =>	killch <-= timeopid;	# may already have been killed
	}
	donech <-= 0;
}

# note: this function must always kill the timeout proc on "normal" returns (i.e. without raising an exception).
_cgiproc(path: string, op: ref Op, cgipath, cgiaction: string, cgitype: int, length: big, needcontinue: int, timeopid: int, cgich: chan of int)
{
	# pid ends up in timeout(), this proc is killed if it doesn't respond timely
	pid := sys->pctl(0, nil);
	cgich <-= pid;

	id := op.id;
	req := op.req;
	resp := op.resp;

	if(debugflag) say(id, sprint("handling cgi request, cgipath %q cgiaction %q cgitype %s, pid %d timeopid %d", cgipath, cgiaction, cgitypes[cgitype], pid, timeopid));

	fd0, fd1: ref Sys->FD;
	if(cgitype == Scgi) {
		scgidialch <-= (cgiaction, replychan := chan of (ref Sys->FD, string));
		(sfd, serr) := <-replychan;
		if(serr != nil) {
			warn(op.id, serr);
			killch <-= timeopid;
			return responderrmsg(op, Eservererror, "Internal Server Error: Handler not reachable");
		}

		sreq := scgirequest(path, cgipath, req, op, length);
		if(sys->write(sfd, sreq, len sreq) != len sreq) {
			warn(id, sprint("write scgi request: %r"));
			killch <-= timeopid;
			return responderrmsg(op, Eservererror, nil);
		}
		fd0 = fd1 = sfd;
	} else {
		err: string;
		cgispawnch <-= (cgiaction, path, cgipath, op, length, replych := chan of (ref Sys->FD, ref Sys->FD, string));
		(fd0, fd1, err) = <-replych;
		if(err != nil) {
			warn(id, "cgispawn: "+err);
			killch <-= timeopid;
			return responderrmsg(op, Eservererror, nil);
		}
	}

	sb := bufio->fopen(fd1, Bufio->OREAD);
	if(sb == nil) {
		warn(id, sprint("bufio fopen cgi fd: %r"));
		killch <-= timeopid;
		return responderrmsg(op, Eservererror, nil);
	}

	if(length > big 0)
		spawn cgifunnel(op.id, op.inb, fd0, length);

	# we always want a "status: ..." line from the cgi program.  it would be better if we would
	# generate a "200 ok" if the status is missing, but we cannot parse the full http request
	# after we've already read the first line (with a header in it) from the iobuf...

	rerr: string;
	hdrs: ref Hdrs;
	for(;;) {
		l := sb.gets('\n');
		killch <-= timeopid;
		if(l == nil) {
			warn(id, "eof from cgi handler while reading response line");
			return responderrmsg(op, Eservererror, "Internal Server Error: EOF from handler");
		}
		l = l[:len l-1];
		if(l != nil && l[len l-1] == '\r')
			l = l[:len l-1];

		if(!str->prefix("status:", str->tolower(l))) {
			warn(id, sprint("bad cgi response line: %q", l));
			return responderrmsg(op, Eservererror, "Internal Server Error: Handler sent bad response line");
		}
		l = str->drop(l[len "status:":], " \t");
		(resp.st, resp.stmsg) = str->splitstrl(l, " ");
		if(resp.stmsg != nil)
			resp.stmsg = droptl(resp.stmsg[1:], " \t");
		if(len resp.st != 3 || str->drop(resp.st, "0-9") != "") {
			warn(id, sprint("bad cgi response line: %q", l));
			return responderrmsg(op, Eservererror, "Internal Server Error: Handler sent bad response line");
		}

		(hdrs, rerr) = Hdrs.read(sb);
		if(rerr != nil) {
			warn(id, "reading cgi headers: "+rerr);
			return responderrmsg(op, Eservererror, "Internal Server Error: Error reading headers from handler");
		}

		if(resp.st == "100") {
			needcontinue = 0;
			fprint(op.fd, "HTTP/1.1 100 Continue\r\n\r\n");
			continue;
		}
		if(needcontinue)
			fprint(op.fd, "HTTP/1.1 100 Continue\r\n\r\n");
		break;
	}

	elength := big -1;
	if(hdrs.has("content-length", nil)) {
		elengthstr := hdrs.get("content-length");
		if(elengthstr == nil || str->drop(elengthstr, "0-9") != "") {
			warn(id, sprint("bad cgi content-length header: %q", elengthstr));
			return responderrmsg(op, Eservererror, "Internal Server Error: Invalid content-length from handler");
		}
		op.length = elength = big elengthstr;
	}
	for(hl := hdrs.all(); hl != nil; hl = tl hl)
		resp.h.add((hd hl).t0, (hd hl).t1);

	accesslog(op);

	op.chunked = elength == big -1 && resp.version() >= HTTP_11;
	rerr = hresp(resp, op.fd, op.keepalive, op.chunked);
	if(rerr != nil) {
		warn(id, "writing response: "+rerr);
		return;
	}

	if(req.method == HEAD)
		return;

	for(;;) {
		n := sb.read(d := array[Sys->ATOMICIO] of byte, len d);
		if(n < 0)
			die(id, sprint("reading file: %r"));
		if(n == 0) {
			if(elength > big 0)
				die(id, "bad cgi body, message shorter than content-length specified");
			break;
		}
		if(elength > big 0) {
			if(big n > elength)
				die(id, "bad cgi body, message longer than content-length specified");
			elength -= big n;
		}
		# for last bit of data, verify that the handler is finished writing
		if(elength > big n || (big n == elength && sb.read(tmp := array[1] of byte, len tmp) != 0))
			die(id, "bad cgi body, message longer than content-length specified");
		hwrite(op, d[:n]);
	}
	hwriteeof(op);
	if(debugflag) say(id, "request done");
}

cgifunnel(id: int, b: ref Iobuf, sfd: ref Sys->FD, length: big)
{
	while(length > big 0) {
		need := Sys->ATOMICIO;
		if(big need > length)
			need = int length;
		n := b.read(d := array[need] of byte, len d);
		if(n < 0)
			die(id, sprint("cgi read: %r"));
		if(n == 0)
			die(id, "cgi read: premature eof");
		{
			if(sys->write(sfd, d, n) != n)
				die(id, sprint("cgi write: %r"));
		} exception {
		* =>	die(id, sprint("cgi write: write on broken pipe"));
		}
		length -= big n;
	}
}

cgivars(path, cgipath: string, op: ref Op, length: big, environ: list of (string, string)): list of (string, string)
{
	servername := op.req.h.get("host");
	if(servername == nil)
		servername = op.lhost;
	pathinfo := path[len cgipath:];
	query := op.req.url.query;
	if(query != nil)
		query = query[1:];
	return	("CONTENT_LENGTH",	string length)::
		("GATEWAY_INTERFACE",	"CGI/1.1")::
		("SERVER_PROTOCOL",	http->versionstr(op.req.version()))::
		("SERVER_NAME",		servername)::
		("REQUEST_METHOD",	op.req.methodstr)::
		("REQUEST_URI",		op.req.url.packpath())::
		("SCRIPT_NAME",		cgipath)::
		("PATH_INFO",		pathinfo)::
		("PATH_TRANSLATED",	pathinfo)::
		("QUERY_STRING",	query)::
		("SERVER_ADDR",		op.lhost)::
		("SERVER_PORT",		op.lport)::
		("REMOTE_ADDR",		op.rhost)::
		("REMOTE_PORT",		op.rport)::
		("SERVER_SOFTWARE",	Version)::
		environ;
}

scgirequest(path, scgipath: string, req: ref Req, op: ref Op, length: big): array of byte
{
	l := ("SCGI", "1")::cgivars(path, scgipath, op, length, environment);
	s := "";
	for(h := l; h != nil; h = tl h)
		s += (hd h).t0+"\0"+(hd h).t1+"\0";
	for(h = req.h.all(); h != nil; h = tl h)
		s += cgivar((hd h).t0)+"\0"+(hd h).t1+"\0";
	return netstring(s);
}

cgivar(s: string): string
{
	r := "HTTP_";
	for(i := 0; i < len s; i++)
		if(s[i] != '-')
			r[len r] = s[i];
		else
			r[len r] = '_';
	return str->toupper(r);
}

netstring(s: string): array of byte
{
	return array of byte (sprint("%d:", len s)+s+",");
}


hresp(resp: ref Resp, fd: ref Sys->FD, keepalive, chunked: int): string
{
	if(keepalive)
		resp.h.add("connection", "keep-alive");
	else
		resp.h.add("connection", "close");
	if(chunked) {
		resp.h.add("transfer-encoding", "chunked");
		resp.h.del("content-length", nil);
	}
	return resp.write(fd);
}

hwrite(op: ref Op, d: array of byte)
{
	if(len d == 0)
		return;

	if(op.chunked) {
		length := array of byte sprint("%x\r\n", len d);
		nd := array[len length+len d+2] of byte;
		nd[:] = length;
		nd[len length:] = d;
		nd[len length+len d:] = array of byte "\r\n";
		d = nd;
	}
	if(sys->write(op.fd, d, len d) != len d)
		die(op.id, sprint("writing response data: %r"));
}

hwriteeof(op: ref Op)
{
	if(op.chunked)
		fprint(op.fd, "0\r\n\r\n");
}

respond(op: ref Op, st: int, errmsgstr: string, ct: string)
{
	resp := op.resp;
	resp.st = string st;
	resp.stmsg = statusmsg(st);
	if(ct != nil)
		resp.h.set("content-type", ct);

	op.chunked = 0;
	errmsg := array of byte errmsgstr;
	op.length = big len errmsg;
	if(!(st >= 100 && st < 200 || st == 204 || st == 304))
		resp.h.set("content-length", string op.length);

	err := hresp(resp, op.fd, op.keepalive, op.chunked);
	if(err != nil)
		die(op.id, "writing error response: "+err);

	if(errmsgstr != nil && (op.req == nil || op.req.method != HEAD)) {
		hwrite(op, errmsg);
		hwriteeof(op);
	}

	accesslog(op);
}

responderr(op: ref Op, st: int)
{
	return respond(op, st, nil, nil);
}

responderrmsg(op: ref Op, st: int, errmsg: string)
{
	if(errmsg == nil)
		errmsg = statusmsg(st);
	return respond(op, st, mkhtml(sprint("%d - %s", st, errmsg)), "text/html; charset=utf-8");
}

statusmsg(code: int): string
{
	for(i := 0; i < len statusmsgs && statusmsgs[i].t0 <= code; i++)
		if(code == statusmsgs[i].t0)
			return statusmsgs[i].t1;
	raise sprint("missing status message for code %d", code);
}

dnslookup(dnsch: chan of string, respch: chan of (string, string))
{
	path := "/net/dns";
	for(;;) {
		ip := <-dnsch;

		revip, err: string;
		l: list of string;
		fd := sys->open(path, Sys->ORDWR);
		if(fd == nil) {
			err = sprint("open %q: %r", path);
		} else {
			(l, err) = reversedns(fd, ip);
			if(len l > 1)
				err = "too many results";
			else if(len l == 0 && err == nil)
				err = "no results";
			else if(len l == 1)
				revip = hd l;
			
		}
		respch <-= (revip, err);
	}
}

reversedns(fd: ref Sys->FD, ip: string): (list of string, string)
{
	(nil, l) := sys->tokenize(ip, ".");
	if(len l != 4)
		return (nil, "invalid ip address");
	dst := "";
	for(; l != nil; l = tl l)
		dst = hd l+"."+dst;
	dst += "in-addr.arpa";
	if(fprint(fd, "%s ptr", dst) < 0)
		return (nil, sprint("%r"));
	r: list of string;
	for(;;) {
		have := sys->read(fd, d := array[1024] of byte, len d);
		if(have < 0)
			return (nil, sprint("read: %r"));
		if(have == 0)
			break;
		(nil, l) = sys->tokenize(string d[:have], " \t");
		if(len l != 3 || hd tl l != "ptr" || hd l != dst)
			continue;
		r = (hd tl tl l)::r;
	}
	return (r, nil);
}

logger()
{
	accessfd: ref Sys->FD;
	backlog := array[0] of (string, string);

	ip, msg: string;
	respch := chan of (string, string);
	dnsch := chan of string;

	spawn dnslookup(dnsch, respch);

	for(;;) alt {
	(logip, s) := <-logch =>
		if(accessfd == nil)
			continue;
		if(msg != nil) {
			na := array[len backlog+1] of (string, string);
			na[:] = backlog;
			na[len backlog] = (logip, s);
			backlog = na;
		} else {
			msg = s;
			ip = logip;
			dnsch <-= logip;
		}

	(revip, err) := <-respch =>
		if(err != nil)
			say(0, sprint("reverse dns lookup %q: %s", ip, err));
		if(fprint(accessfd, "%s %q\n", msg, revip) < 0)
			warn(0, sprint("writing access log message: %r"));
		msg = nil;
		if(len backlog != 0) {
			(ip, msg) = backlog[0];
			backlog = backlog[1:];
			dnsch <-= ip;
		}

	accessfd = <-logfdch =>
		;
	}
}

accesslog(op: ref Op)
{
	if(op.cfgs.accessfd == nil && !debugflag)
		return;

	length := "";
	if(!op.chunked && op.length >= big 0)
		length = string op.length;

	s := sprint("%d %d %s!%s %s!%s %q %q %q HTTP/%d.%d %q %q %q %q %q",
		op.id, op.now,
		op.rhost, op.rport, op.lhost, op.lport,
		op.req.methodstr, op.req.h.get("host"), op.req.url.path+op.req.url.query,
		op.req.major, op.req.minor, op.resp.st, op.resp.stmsg,
		length,
		op.req.h.get("user-agent"), op.req.h.get("referer"));
	logch <-= (op.rhost, s);
	if(debugflag) say(op.id, "accesslog: "+s);
}

splithost(s: string): (string, string)
{
	host: string;
	if(str->prefix("[", s)) {
		# "[ip6]"
		(ip, rem) := str->splitstrl(s[1:], "]");
		if(!str->prefix("]", rem))
			return (nil, nil);
		s = rem[1:];
		(ok, ipaddr) := IPaddr.parse(ip);
		if(ok != 0)
			return (nil, nil);
		# canonical form, eg for ipv4 mapped on ipv6
		host = ipaddr.text();
	} else
		(host, s) = str->splitstrl(s, ":");
	if(str->prefix(":", s))
		s = s[1:];
	return (host, s);
}

suffix(suf, s: string): int
{
	if(len suf > len s)
		return 0;
	return suf == s[len s-len suf:];
}

mimetype(cfgs: ref Cfgs, path: string): string
{
	for(t := cfgs.usertypes; t != nil; t = tl t)
		if(suffix((hd t).t0, path))
			return (hd t).t1;
	for(i := 0; i < len mimetypes; i++)
		if(suffix(mimetypes[i].t0, path))
			return mimetypes[i].t1;
	if(!haschar(str->splitstrr(path, "/").t1, '.'))
		return "text/plain; charset=utf-8";	# for mkfile, README, etc.
	return nil;
}

hasbody(req: ref Req): int
{
	return req.h.has("content-length", nil) || req.h.has("transfer-encoding", nil);
}

days := array[] of {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
months := array[] of {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

httpdate(t: int): string
{
	tm := daytime->gmt(t);
	return sprint("%s, %02d %s %d %02d:%02d:%02d GMT", days[tm.wday], tm.mday, months[tm.mon], tm.year+1900, tm.hour, tm.min, tm.sec);
}

readtoken(s: string): (string, string, string)
{
	for(i := 0; i < len s; i++)
		if(s[i] < ' ')
			return (nil, nil, "invalid control characters found");
		else if(str->in(s[i], "()<>@,;:\\\"/[]?={} \t"))
			break;
	return (s[:i], s[i:], nil);
}

# read list of bare tokens
tokenize(s: string): (list of string, string)
{
	token, err: string;
	l: list of string;
	for(;;) {
		(token, s, err) = readtoken(s);
		if(err != nil)
			return (nil, err);
		if(token != nil)
			l = token::l;
		s = str->drop(s, " \t");
		if(s == nil)
			break;
		if(s[0] != ',')
			return (nil, "expected comma as separator");
		s = str->drop(s, ", \t");
	}
	return (rev(l), nil);
}

# read double quoted token in header.
# for http/1.1 a backslash may be used for escaping, not for http/1.0
readqs(s: string, v: int): (string, string, string)
{
	if(s == nil)
		return (nil, nil, nil);
	if(s[0] != '"')
		return (nil, s, nil);
	r := "\"";
	for(i := 1; i < len s; i++)
		if(s[i] < ' ')
			return (nil, nil, "invalid control character found inside quoted string");
		else if(v >= HTTP_11 && s[i] == '\\' && i+1 < len s && s[i+1] == '"')
			r[len r] = s[++i];
		else {
			r[len r] = s[i];
			if(s[i] == '"')
				return (r, s[i+1:], nil);
		}
	return (nil, nil, "quoted string not ended");
}

# read list of double-quoted strings
tokenizeqs(s: string, v: int): (list of string, string)
{
	r: list of string;
	qs, err: string;
	for(;;) {
		(qs, s, err) = readqs(s, v);
		if(err != nil)
			return (nil, err);
		if(qs != nil)
			r = qs::r;
		s = str->drop(s, " \t");
		if(s == nil)
			break;
		if(s[0] != ',')
			return (nil, "expected comma as separator");
		s = str->drop(s, ", \t");
	}
	return (rev(r), nil);
}

# i'm not going to parse three different date formats where a simple unix epoch integer would have sufficed.
# death to the bloat monster!
parsehttpdate(s: string): int
{
	mday, mon, year, hour, min, sec: int;

	# sys-tokenize allows too much whitespace, but well...
	(n, tokens) := sys->tokenize(s, " ");
	if(n != 6 || len hd tokens != 4 || (hd tokens)[3] != ',' || index(days, (hd tokens)[:3]) < 0)
		return 0;
	if((mon = index(months, hd tl tl tokens)) < 0)
		return 0;
	(hn, htokens) := sys->tokenize(hd tl tl tl tl tokens, ":");
	if(hn != 3)
		return 0;
	mday = int hd tl tokens;
	year = int hd tl tl tl tokens;
	hour = int hd htokens;
	min = int hd tl htokens;
	sec = int hd tl tl htokens;

	# last arg should be seconds offset for timezone, "luckily" http allows only gmt...
	return daytime->tm2epoch(ref Daytime->Tm(sec, min, hour, mday, mon, year-1900, 0, 0, s[1:], 0));
}

parserange(version: int, rangehdr: (int, string), length: big): (int, list of ref (big, big))
{
	(haverange, range) := rangehdr;
	if(!haverange || !(version >= HTTP_11))
		return (1, nil);

	if(!str->prefix("bytes", range))
		return (0, nil);
	range = range[len "bytes":];
	range = str->drop(range, " \t");
	if(!str->prefix("=", range))
		return (0, nil);
	range = str->drop(range[1:], " \t");

	# warning: range header parsing is fairly abstruse
	r: list of ref (big, big);
	valid := 0;
	for(l := sys->tokenize(range, ",").t1; l != nil; l = tl l) {
		s := strip(hd l, " \t");
		if(s == nil)
			continue;
		if(s[0] == '-') {
			# single (negative) byte offset relative to end of file
			s = str->drop(s[1:], " \t");
			if(s == nil || str->drop(s, "0-9") != nil)
				return (1, nil);
			if(big s != big 0)
				valid = 1;
			i := length - big s;
			if(i < big 0)
				i = big 0;
			if(i >= length)
				i = length - big 1;
			r = ref (i, length)::r;
		} else {
			(first, last) := str->splitstrl(s, "-");
			if(stripws(str->drop(first, "0-9")) != nil || last == nil || str->drop(stripws(last[1:]), "0-9") != nil)
				return (1, nil);
			f := big first;
			e := length;
			last = stripws(last[1:]);
			if(last != nil)
				e = big last+big 1;
			if(e > length)
				e = length;
			if(f > e)
				return (1, nil);
			if(f < length)
				valid = 1;
			r = ref (f, e)::r;
		}
	}
	return (valid, rev(r));
}

listingssort(cfg: ref Cfg)
{
	sort(cfg.listings, listingge);
}

sort[T](a: array of T, ge: ref fn(a, b: T): int)
{
	for(i := 1; i < len a; i++) {
		tmp := a[i];
		for(j := i; j > 0 && ge(a[j-1], tmp); j--)
			a[j] = a[j-1];
		a[j] = tmp;
	}
}

listingge(e1, e2: ref (string, int)): int
{
	return len e1.t0 < len e2.t0;
}

strip(s, cl: string): string
{
	return droptl(str->drop(s, cl), cl);
}

stripws(s: string): string
{
	return strip(s, " \t");
}

droptl(s, cl: string): string
{
	while(s != nil && str->in(s[len s-1], cl))
		s = s[:len s-1];
	return s;
}

index(a: array of string, s: string): int
{
	for(i := 0; i < len a; i++)
		if(a[i] == s)
			return i;
	return -1;
}

readaddr(id: int, path: string): (string, string)
{
	(s, err) := readfileline(path, 256);
	if(err != nil)
		die(id, err);
	(lhost, lport) := str->splitstrl(s, "!");
	if(lport != nil)
		lport = lport[1:];
	return (lhost, lport);
}

readfileline(path: string, maxsize: int): (string, string)
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil)
		return (nil, sprint("open %s: %r", path));
	n := sys->read(fd, buf := array[maxsize] of byte, len buf);
	if(n < 0)
		return (nil, sprint("read %s: %r", path));
	s := string buf[:n];
	if(s != nil && s[len s-1] == '\n')
		s = s[:len s-1];
	return (s, nil);
}

readtime(): int
{
	n := sys->pread(timefd, d := array[64] of byte, len d, big 0);
	if(n < 0)
		fail(sprint("reading time: %r"));
	return int ((big string d[:n])/big 1000000);
}

byte2str(a: array of byte): string
{
	s := "";
	for(i := 0; i < len a; i++)
		s += sprint("%02x", int a[i]);
	return s;
}

sha1(a: array of byte): string
{
	r := array[keyring->SHA1dlen] of byte;
	keyring->sha1(a, len a, r, nil);
	return byte2str(r);
}

listhas(l: list of string, s: string): int
{
	for(; l != nil; l = tl l)
		if(str->tolower(hd l) == s)
			return 1;
	return 0;
}

haschar(s: string, c: int): int
{
	for(i := 0; i < len s; i++)
		if(s[i] == c)
			return 1;
	return 0;
}

hasmethod(l: list of string, v: string): int
{
	for(; l != nil; l = tl l)
		if(hd l == v)
			return 1;
	return 0;
}

substr(sub, s: string): int
{
	return str->prefix(sub, str->splitstrl(s, sub).t1);
}

rev[T](l: list of T): list of T
{
	r: list of T;
	for(; l != nil; l = tl l)
		r = hd l::r;
	return r;
}

kill(pid: int)
{
	fd := sys->open(sprint("/prog/%d/ctl", pid), Sys->OWRITE);
	if(fd != nil)
		fprint(fd, "kill");
}

say(id:int, s: string)
{
	msec := sys->millisec();
	if(debugflag)
		fprint(fildes(2), "%d %d, %s\n", msec, id, s);
	if(debugflag && errorfd != nil)
		fprint(errorfd, "%d %d, %s\n", msec, id, s);
}

warn(id: int, s: string)
{
	msec := sys->millisec();
	if(debugflag)
		fprint(fildes(2), "%d %d, %s\n", msec, id, s);
	if(errorfd != nil)
		fprint(errorfd, "%d %d, %s\n", msec, id, s);
}

die(id: int, s: string)
{
	warn(id, s);
	raise "fail:"+s;
}

fail(s: string)
{
	fprint(fildes(2), "%s\n", s);
	raise "fail:"+s;
}


# reading the config file

Cfgs.init(file: string): (ref Cfgs, string)
{
	db := Db.open(file);
	if(db == nil)
		return (nil, sprint("open config %q: %r", file));
	return Cfgs.read(file, db);
}

Cfgs.read(file: string, db: ref Db): (ref Cfgs, string)
{
	c := ref Cfgs(file, db, Cfg.new(), nil, nil, 0, 0, nil, nil);
	logfile: string;

	e: ref Dbentry; 
	(e, nil) = c.db.find(nil, "vhost");
	if(e != nil)
		c.vhostflag = 1;
	(e, nil) = c.db.find(nil, "novhost");
	if(e != nil)
		c.vhostflag = 0;

	(e, nil) = c.db.find(nil, "debug");
	if(e != nil)
		c.debugflag = 1;
	(e, nil) = c.db.find(nil, "nodebug");
	if(e != nil)
		c.debugflag = 0;

	(e, nil) = c.db.find(nil, "ctlchan");
	if(e != nil) {
		s := e.findfirst("ctlchan");
		if(s != nil)
			ctlchan = s;
	}

	(e, nil) = c.db.find(nil, "accesslog");
	if(e != nil) {
		s := e.findfirst("accesslog");
		if(s != nil)
			logfile = s;
	}

	ptr: ref Attrdb->Dbptr;
	attr := "mime";
	for(;;) {
		(e, ptr) = c.db.find(ptr, attr);
		if(e == nil)
			break;
		ext := e.findfirst("ext");
		mtype := e.findfirst("type");
		if(ext == nil || mtype == nil)
			return (nil, sprint("bad mime type, ext=%q type=%q", ext, mtype));
		c.usertypes = ref (ext, mtype)::c.usertypes;
	}
	ptr = nil;

	attr = "announce";
	for(;;) {
		(e, ptr) = c.db.find(ptr, attr);
		if(e == nil)
			break;
		c.addrs = e.findfirst("announce")::c.addrs;
	}
	ptr = nil;

	attr = "host";
	for(;;) {
		(e, ptr) = c.db.find(ptr, attr);
		if(e == nil)
			break;
		host := e.findfirst("host");
		port := e.findfirst("port");
		if(port == nil)
			port = "80";
		(cfg, err) := Cfg.read(e, port);
		if(err != nil)
			return (nil, err);
		if(host == "*")
			host = "";
		cfg.host = host;
		cfg.port = string int port;
		if(host == nil)
			c.default = cfg;
		c.cfgs = (host, port, cfg)::c.cfgs;
	}
	ptr = nil;

	attr = "alias";
	for(;;) {
		(e, ptr) = c.db.find(ptr, attr);
		if(e == nil)
			break;
		host := e.findfirst("host");
		port := e.findfirst("port");
		usehost := e.findfirst("usehost");
		useport := e.findfirst("useport");
		if(port == nil)
			port = "80";
		if(usehost == nil)
			usehost = host;
		if(useport == nil)
			useport = port;
		if(usehost == host && useport == port)
			return (nil, "alias line aliases host and port to itself, ignoring");
		cfg := c.find(usehost, string int useport);
		if(cfg == nil)
			return (nil, sprint("alias references non-existing usehost=%q useport=%q", usehost, useport));
		c.cfgs = (host, string int port, cfg)::c.cfgs;
	}
	ptr = nil;

	if(logfile != nil) {
		c.accessfd = sys->open(logfile, Sys->OWRITE);
		if(c.accessfd == nil)
			return (nil, sprint("open logfile %q: %r", logfile));
		sys->seek(c.accessfd, big 0, Sys->SEEKEND);
	}
	c.usertypes = rev(c.usertypes);

	return (c, nil);
}

Cfgs.find(c: self ref Cfgs, host, port: string): ref Cfg
{
	for(l := c.cfgs; l != nil; l = tl l) {
		(chost, cport, config) := hd l;
		if(host == chost && port == cport)
			return config;
	}
	return c.default;
}


Cfg.new(): ref Cfg
{
	return ref Cfg("", "80", array[0] of ref (string, int), -1, nil, nil, nil, nil, nil, nil);
}

Cfg.read(e: ref Dbentry, defaultport: string): (ref Cfg, string)
{
	cfg := Cfg.new();

	for(l := list of {"cachesecs"}; l != nil; l = tl l) {
		for(r := e.find(hd l); r != nil; r = tl r) {
			for(attrs := (hd r).t1; attrs != nil; attrs = tl attrs) {
				val := (hd attrs).val;
				case (hd attrs).attr {
				"cachesecs" =>
					cfg.cachesecs = int val;
				* =>
					warn(0, sprint("ignoring config attribute %q", (hd attrs).attr));
				}
			}
		}
	}

	for(l = list of {"listings", "nolistings", "listen", "redir", "auth", "index", "cgi", "scgi", "gzip"}; l != nil; l = tl l) {
		attr := hd l;
		for(r := e.find(attr); r != nil; r = tl r) {
			(tups, nil) := hd r;
			case attr {
			"listings" or "nolistings" =>
				what := attr == "listings";
				for(pl := tups.find("path"); pl != nil; pl = tl pl) {
					nl := array[len cfg.listings+1] of ref (string, int);
					nl[:] = cfg.listings;
					nl[len cfg.listings] = ref ((hd pl).val, what);
					cfg.listings = nl;
				}

			"listen" =>
				ip := tups.find("ip");
				port := tups.find("port");
				if(ip == nil)
					return (nil, sprint("missing ip in listen line"));
				ipstr := (hd ip).val;
				(ok, ipaddr) := IPaddr.parse(ipstr);
				if(ok != 0)
					return (nil, sprint("invalid ip address: %q", ipstr));
				portstr := defaultport;
				if(port != nil)
					portstr = (hd port).val;
				cfg.listens = (ref (ipaddr.text(), string int portstr))::cfg.listens;

			"redir" =>
				src := tups.find("src");
				dst := tups.find("dst");
				if(src == nil || dst == nil)
					return (nil, "missing src or dst in redir line");
				(repl, rerr) := Repl.parse((hd src).val, (hd dst).val);
				if(rerr != nil)
					return (nil, "parsing redir: "+rerr);
				cfg.redirs = repl::cfg.redirs;

			"auth" =>
				path := tups.find("path");
				realm := tups.find("realm");
				user := tups.find("user");
				pass := tups.find("pass");
				if(path == nil || realm == nil || user == nil || pass == nil)
					return (nil, "missing field in auth line, need path, realm, user and pass");
				if(haschar((hd realm).val, '"'))
					return (nil, "realm must not have double quote, not supported by http/1.0");
				cfg.auths = ref ((hd path).val, (hd realm).val, base64->enc(array of byte ((hd user).val+":"+(hd pass).val)))::cfg.auths;

			"index" =>
				for(file := tups.find("file"); file != nil; file = tl file)
					cfg.indexfiles = (hd file).val::cfg.indexfiles;

			"cgi" =>
				path := tups.find("path");
				cmd := tups.find("cmd");
				if(path == nil || cmd == nil)
					return (nil, "missing path or cmd in cgi line");

				methods: list of string;
				methodtups := tups.find("methods");
				if(methodtups != nil)
					methods = sys->tokenize((hd methodtups).val, " ,").t1;
				cfg.cgipaths = ref ((hd path).val, (hd cmd).val, methods, Cgi)::cfg.cgipaths;

			"scgi" =>
				path := tups.find("path");
				addr := tups.find("addr");
				if(path == nil || addr == nil)
					return (nil, "missing path or addr in scgi line");

				methods: list of string;
				methodtups := tups.find("methods");
				if(methodtups != nil)
					methods = sys->tokenize((hd methodtups).val, " ,").t1;
				cfg.cgipaths = ref ((hd path).val, (hd addr).val, methods, Scgi)::cfg.cgipaths;
			"gzip" =>
				for(pl := tups.find("path"); pl != nil; pl = tl pl)
					cfg.gzpaths = (hd pl).val::cfg.gzpaths;
			}
		}
	}
	cfg.rev();
	return (cfg, nil);
}

Cfg.rev(cfg: self ref Cfg)
{
	cfg.listens = rev(cfg.listens);
	cfg.cgipaths = rev(cfg.cgipaths);
	cfg.indexfiles = rev(cfg.indexfiles);
	cfg.redirs = rev(cfg.redirs);
	cfg.auths = rev(cfg.auths);
	listingssort(cfg);
}


Repl.parse(restr, rulestr: string): (ref Repl, string)
{
	(re, err) := regex->compile(restr, 1);
	if(err != nil)
		return (nil, "bad regex: "+err);

	rule: list of ref (string, int);
	maxrepl := 0;
	for(;;) {
		(l, r) := str->splitstrl(rulestr, "$");
		if(r == nil) {
			rule = ref (l, -1)::rule;
			break;
		}
		r = r[1:];
		if(r != nil && r[0] == '$') {
			rule = ref (l+"$", -1)::rule;
			r = r[1:];
		} else {
			num := str->take(r, "0-9");
			if(num == nil)
				return (nil, "bad rule: $ not followed by number or dollar");
			n := int num;
			if(n > maxrepl)
				maxrepl = n;
			rule = ref (l, n)::rule;
			r = r[len num:];
		}
		rulestr = r;
	}
	rule = rev(rule);
	return (ref Repl(re, rule, maxrepl), nil);
}

Repl.apply(r: self ref Repl, s: string): (int, string, string)
{
	m := regex->executese(r.re, s, (0, len s), 1, 1);
	if(m == nil)
		return (0, nil, nil);
	if(r.maxrepl > len m-1)
		return (0, nil, "replacement group not in groups in regular expression");
	res := "";
	for(rl := r.rule; rl != nil; rl = tl rl) {
		(part, index) := *(hd rl);
		res += part;
		if(index == -1)
			continue;
		(b, e) := m[index];
		if(b == -1 || e == -1)
			return (0, nil, "replacement group did not match in regular expression");
		res += s[b:e];
	}
	return (1, res, nil);
}
