implement Httpd;

include "sys.m";
include "draw.m";
include "arg.m";
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "daytime.m";
include "env.m";
include "string.m";
include "exception.m";
include "mhttp.m";

sys: Sys;
daytime: Daytime;
env: Env;
exc: Exception;
str: String;
http: Http;

print, sprint, fprint, fildes: import sys;
Url, Req, Resp, Hdrs, HTTP_10, HTTP_11, encodepath: import http;
OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT: import http;


Op: adt {
	id, now:	int;
	rhost, rport, lhost, lport:	string;
	req:	ref Req;
	resp:	ref Resp;
};

dflag, hflag, lflag: int;
addr := "net!localhost!8000";
webroot := "";
environment: list of (string, string);

Httpd: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};

types := array[] of {
	(".pdf",	"application/pdf"),
	(".html",	"text/html; charset=utf-8"),
	(".htm",	"text/html; charset=utf-8"),
	(".txt",	"text/plain; charset=utf-8"),
	(".diff",	"text/plain; charset=utf-8"),
	(".patch",	"text/plain; charset=utf-8"),
	(".ps",		"application/postscript"),
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
	(".sh",		"text/plain; charset=utf-8"),
	(".orig",	"text/plain; charset=utf-8"),
	(".conf",	"text/plain; charset=utf-8"),
	(".avi",	"video/x-msvideo"),
	(".bz2",	"application/x-bzip"),
	(".tex",	"text/plain; charset=utf-8"),
	(".mp4",	"video/mp4"),
	(".mpg",	"video/mpeg"),
};

idch: chan of int;

timefd: ref Sys->FD;
errorfd: ref Sys->FD;
accessfd: ref Sys->FD;

scgipaths: list of (string, string);
scgichan: chan of (string, chan of (ref Sys->FD, string));

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;
	env = load Env Env->PATH;
	daytime = load Daytime Daytime->PATH;
	str = load String String->PATH;
	exc = load Exception Exception->PATH;
	http = load Http Http->PATH;
	http->init(bufio);

	arg->init(args);
	arg->setusage(arg->progname()+" [-a addr] [-dhl] [-s path addr] webroot");
	while((c := arg->opt()) != 0)
		case c {
		'a' =>	addr = arg->earg();
		'd' =>	dflag++;
		'h' =>	hflag++;
		'l' =>	lflag++;
			http->debug = 1;
		's' =>	spath := arg->earg();
			saddr := arg->earg();
			scgipaths = (spath, saddr)::scgipaths;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1)
		arg->usage();
	webroot = hd args;

	environment = env->getall();

	sys->pctl(Sys->FORKNS, nil);
	if(sys->chdir(webroot) != 0)
		fail(sprint("chdir webroot %s: %r", webroot));

	timefd = sys->open("/dev/time", Sys->OREAD);
	if(timefd == nil)
		fail(sprint("open /dev/time: %r"));

	errorfd = sys->open("/services/logs/httpderror", Sys->ORDWR);
	accessfd = sys->open("/services/logs/httpdaccess", Sys->ORDWR);
	if(errorfd != nil)
		sys->seek(errorfd, big 0, Sys->SEEKEND);
	if(accessfd != nil)
		sys->seek(accessfd, big 0, Sys->SEEKEND);

	idch = chan[8] of int;
	spawn idgen();

	scgichan = chan of (string, chan of (ref Sys->FD, string));
	spawn scgidialer();

	(aok, aconn) := sys->announce(addr);
	if(aok != 0)
		fail(sprint("announce %s: %r", addr));
	say("announed to "+addr);
	for(;;) {
		(lok, lconn) := sys->listen(aconn);
		if(lok != 0)
			fail(sprint("listen %s: %r", addr));
		dfd := sys->open(lconn.dir+"/data", Sys->ORDWR);
		if(dfd != nil)
			spawn httpserve(dfd, lconn.dir);
		else
			say(sprint("opening data file: %r"));
		lconn.dfd = nil;
	}
}

idgen()
{
	id := 0;
	for(;;)
		idch <-= id++;
}

scgidialer()
{
	for(;;) {
		(scgiaddr, replychan) := <-scgichan;
		spawn scgidial(scgiaddr, replychan);
	}
}

scgidial(scgiaddr: string, replychan: chan of (ref Sys->FD, string))
{
	(ok, conn) := sys->dial(scgiaddr, nil);
	if(ok < 0) {
		say(sprint("dialing scgid %s: %r", scgiaddr));
		replychan <-= (nil, "dialing scgid failed");
	} else
		replychan <-= (conn.dfd, nil);
}

httpserve(fd: ref Sys->FD, conndir: string)
{
	id := <-idch;
	chat(id, "httpserve");

	addr, ferr: string;
	(addr, ferr) = readfileline(conndir+"/local", 256);
	if(ferr != nil)
		die(id, ferr);
	(lhost, lport) := str->splitstrl(addr, "!");
	if(lport != nil)
		lport = lport[1:];
	(addr, ferr) = readfileline(conndir+"/remote", 256);
	if(ferr != nil)
		die(id, ferr);
	(rhost, rport) := str->splitstrl(addr, "!");
	if(rport != nil)
		rport = rport[1:];
	chat(id, sprint("connect from %s:%s to %s:%s", rhost, rport, lhost, lport));

	(ok, sdir) := sys->stat(".");
	if(ok != 0)
		raise "sys-stat not okay";
	say(sprint("current dir: %s", sdir.name));

	op := Op(id, 0, rhost, rport, lhost, lport, nil, nil);

	sys->pctl(Sys->NEWPGRP, nil);
	if(exc->setexcmode(Exception->NOTIFYLEADER) != 0)
		die(id, sprint("setting exception handling: %r"));
	sys->pctl(Sys->NEWNS|Sys->NODEVS, nil);

	(ok, sdir) = sys->stat("/");
	if(ok != 0)
		raise "sys-stat not okay";
	say(sprint("current dir2: %s", sdir.name));

	b := bufio->fopen(fd, Bufio->OREAD);
	if(b == nil)
		die(id, sprint("bufio open: %r"));

	keepalive := 0;

	for(nsrvs := 0; ; nsrvs++) {
		if(nsrvs > 0 && !keepalive)
			break;
		if(sys->chdir("/") != 0)
			break;

		op.now = readtime();
		hdrs := Hdrs.new(("date", httpdate(op.now))::nil);

		(req, rerr) := Req.read(b);
		if(rerr != nil) {
			hdrs.add("connection", "close");
			op.resp = ref Resp(HTTP_10, nil, nil, hdrs);
			respond(0, fd, op, "400", "bad request", "bad request: "+rerr);
			die(id, "reading request: "+rerr);
		}
		chat(id, sprint("request: method %q url %q version %q", http->methodstr(req.method), req.url.pack(), http->versionstr(req.version)));
		op.req = req;

		# xxx host present for http/1.1 (or full url as path)

		http11 := req.version == HTTP_11;
		chunked := http11 && !req.h.has("connection", "close");
		keepalive = chunked;

		if(chunked && keepalive) {
			hdrs.add("transfer-encoding", "chunked");
			hdrs.add("connection", "keep-alive");
		} else {
			hdrs.add("connection", "close");
		}
		op.resp = ref Resp(req.version, "200", "OK", hdrs);

		case req.method {
		GET or HEAD or POST =>
			;
		TRACE =>
			hdrs.add("content-type", "message/http");
			respond(chunked, fd, op, "200", "OK", req.pack());
			continue;

		OPTIONS =>
			# xxx should be based on path
			hdrs.add("allow", "OPTIONS, GET, HEAD, POST, TRACE");
			respond(chunked, fd, op, "200", "OK", "");
			continue;

		PUT or DELETE =>
			respond(chunked, fd, op, "501", "not implemented", "method not implemented");
			continue;

		* =>
			respond(chunked, fd, op, "400", "bad request", "unknown method");
			return;
		}

		path := pathsanitize(req.url.path);
		chat(id, "path is "+path);

		(havehost, hostdir) := req.h.find("host");
		if(!havehost) {
			hostdir = "_default";
		} else {
			(hostdir, nil) = str->splitstrl(hostdir, ":");
			if(str->drop(hostdir, "0-9a-zA-Z.-") != nil || str->splitstrl(hostdir, "..").t1 != nil) {
				chat(id, "bad host in header");
				respond(chunked, fd, op, "404", "file not found", "object not found: "+path);
				continue;
			}
		}
		if(hflag && sys->chdir(hostdir) != 0) {
			hostdir = "_default";
			if(havehost && sys->chdir(hostdir) != 0) {
				respond(chunked, fd, op, "404", "file not found", "object not found: "+path);
				continue;
			}
		}

		if(((scgipath, scgiaddr) := findscgi(path)).t1 != nil) {
			scgi(chunked, fd, path, op, scgipath, scgiaddr);
			continue;
		}

		dfd := sys->open("."+path, Sys->OREAD);
		if(dfd == nil || ((nil, dir) := sys->fstat(dfd)).t0 != 0 || (dir.mode&Sys->DMDIR) && (!lflag || path != nil && path[len path-1] != '/')) {
			chat(id, "file not found");
			respond(chunked, fd, op, "404", "file not found", "object not found: "+path);
			continue;
		}

		accesslog(op);

		if(dir.mode & Sys->DMDIR)
			listdir(chunked, fd, path, op, dfd);
		else
			plainfile(chunked, fd, path, op, dfd);
	}
}

plainfile(chunked: int, fd: ref Sys->FD, path: string, op: Op, dfd: ref Sys->FD)
{
	id := op.id;
	resp := op.resp;

	if(op.req.method == POST) {
		respond(chunked, fd, op, "405", "method not allowed", "POST not allowed on files");
		return;
	}

	chat(id, "doing plain file");
	resp.h.add("content-type", gettype(path));
	rerr := resp.write(fd);
	if(rerr != nil)
		die(id, "writing response: "+rerr);

	if(op.req.method == HEAD)
		return;

	for(;;) {
		n := sys->read(dfd, d := array[Sys->ATOMICIO] of byte, len d);
		if(n < 0)
			die(id, sprint("reading file: %r"));
		if(n == 0)
			break;
		hwrite(chunked, fd, d[:n]);
	}
	hwriteeof(chunked, fd);
}

listdir(chunked: int, fd: ref Sys->FD, path: string, op: Op, dfd: ref Sys->FD)
{
	id := op.id;
	resp := op.resp;

	if(op.req.method == POST) {
		respond(chunked, fd, op, "405", "method not allowed", "POST not allowed on directories");
		return;
	}

	chat(id, "doing directory listing");
	resp.h.add("content-type", "text/html");
	rerr := resp.write(fd);
	if(rerr != nil)
		die(id, "writing response: "+rerr);

	if(op.req.method == HEAD)
		return;

	begin := sprint("<html><head><style type=\"text/css\">h1 { font-size: 1.4em; } td, th { padding-left: 1em; padding-right: 1em; } td.mtime, td.size { text-align: right; }</style><title>listing for %s</title></head><body><h1>listing for %s</h1><hr/><table><tr><th>last modified</th><th>size</th><th>name</th></tr>\n", path, pathurls(path));
	hwrite(chunked, fd, array of byte begin);
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
			html += sprint("<tr><td class=\"mtime\">%s</td><td class=\"size\">%bd</td><td class=\"name\"><a href=\"%s\">%s</a></td></tr>\n", daytime->filet(op.now, d[i].mtime), d[i].length, htmlescape(encodepath(name)), htmlescape(name));
		}
		hwrite(chunked, fd, array of byte html);
	}
	end := sprint("</table><hr/></body></html>\n");
	hwrite(chunked, fd, array of byte end);
	hwriteeof(chunked, fd);
}

scgi(chunked: int, fd: ref Sys->FD, path: string, op: Op, scgipath, scgiaddr: string)
{
	id := op.id;
	req := op.req;
	resp := op.resp;

	if(req.method == HEAD) {
		respond(chunked, fd, op, "501", "not implemented", "HEAD on scgi paths not implemented");
		return;
	}

	if(req.method == POST && !req.h.has("content-length", nil)) {
		respond(chunked, fd, op, "400", "bad request", "POST needs a content-length");
		return;
	}
	length := int req.h.get("content-length");

	chat(id, sprint("handling scgi request, scgipath %q scgiaddr %q", scgipath, scgiaddr));
	scgichan <-= (scgiaddr, replychan := chan of (ref Sys->FD, string));
	(sfd, serr) := <-replychan;
	if(serr != nil) {
		respond(chunked, fd, op, "503", "internal server error", "internal server error");
		die(id, serr);
	}

	sreq := scgirequest(path, scgipath, req, op, length);
	if(sys->write(sfd, sreq, len sreq) != len sreq) {
		respond(chunked, fd, op, "503", "internal server error", "internal server error");
		die(id, sprint("write scgi request: %r"));
	}

	if(length > 0)
		spawn scgifunnel(fd, sfd, length);

	sb := bufio->fopen(sfd, Bufio->OREAD);
	if(sb == nil) {
		respond(chunked, fd, op, "503", "internal server error", "internal server error");
		die(id, sprint("bufio fopen scgi fd: %r"));
	}

	l := sb.gets('\n');
	if(!str->prefix("Status: ", l)) {
		respond(chunked, fd, op, "503", "internal server error", "internal server error");
		die(id, "bad scgi response line: "+l);
	}
	l = l[len "Status: ":];
	(st, stmsg) := str->splitstrl(l, " ");
	if(stmsg != nil)
		stmsg = stmsg[1:];
	while(stmsg != nil && str->in(stmsg[len stmsg-1], "\r\n"))
		stmsg = stmsg[:len stmsg-1];
	resp.st = st;
	resp.stmsg = stmsg;

	accesslog(op);

	(hdrs, rerr) := Hdrs.read(sb);
	if(rerr != nil) {
		respond(chunked, fd, op, "503", "internal server error", "internal server error");
		die(id, "reading scgi headers: "+rerr);
	}
	for(hl := hdrs.all(); hl != nil; hl = tl hl)
		resp.h.add((hd hl).t0, (hd hl).t1);

	rerr = resp.write(fd);
	if(rerr != nil)
		die(id, "writing response: "+rerr);

	for(;;) {
		n := sys->read(sfd, d := array[Sys->ATOMICIO] of byte, len d);
		if(n < 0)
			die(id, sprint("reading file: %r"));
		if(n == 0)
			break;
		hwrite(chunked, fd, d[:n]);
	}
	hwriteeof(chunked, fd);
	chat(id, "request done");
}

scgifunnel(fd, sfd: ref Sys->FD, length: int)
{
	while(length > 0) {
		n := sys->read(fd, d := array[Sys->ATOMICIO] of byte, len d);
		if(n < 0)
			fail(sprint("fail:scgi read: %r"));
		if(n == 0)
			fail(sprint("fail:scgi read: premature eof"));
		if(sys->write(sfd, d, n) != n)
			fail(sprint("fail:scgi write: %r"));
		length -= n;
	}
}

hwrite(chunked: int, fd: ref Sys->FD, d: array of byte)
{
	if(len d == 0)
		return;

	if(chunked) {
		length := array of byte sprint("%x\r\n", len d);
		nd := array[len length+len d+2] of byte;
		nd[:] = length;
		nd[len length:] = d;
		nd[len length+len d:] = array of byte "\r\n";
		d = nd;
	}
	if(sys->write(fd, d, len d) != len d)
		fail(sprint("writing response: %r"));
}

hwriteeof(chunked: int, fd: ref Sys->FD)
{
	if(chunked)
		fprint(fd, "0\r\n\r\n");
}

respond(chunked: int, fd: ref Sys->FD, op: Op, st, stmsg, errmsg: string)
{
	resp := op.resp;
	resp.st = st;
	resp.stmsg = stmsg;
	if(!resp.h.has("content-type", nil))
		resp.h.add("content-type", "text/plain");
	err := resp.write(fd);
	if(err != nil)
		die(op.id, "writing error response: "+err);

	if(op.req == nil || op.req.method != HEAD) {
		hwrite(chunked, fd, array of byte errmsg);
		hwriteeof(chunked, fd);
	}

	accesslog(op);
}

accesslog(op: Op)
{
	if(accessfd != nil && op.req != nil)
		fprint(accessfd, "%d %d %s!%s %s!%s %q %q %q %q %q %q\n", op.id, op.now, op.rhost, op.rport, op.lhost, op.lport, http->methodstr(op.req.method), op.req.url.pack(), http->versionstr(op.req.version), op.resp.st, op.resp.stmsg, op.req.h.get("user-agent"));
}

findscgi(path: string): (string, string)
{
	for(l := scgipaths; l != nil; l = tl l)
		if(str->prefix((hd l).t0, path))
			return hd l;
	return (nil, nil);
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

pathsanitize(path: string): string
{
	say("path sanitize: "+path);
	trailslash := path != nil && path[len path-1] == '/';

	(nil, elems) := sys->tokenize(path, "/");
	say(sprint("path nelems: %d", len elems));
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

pathurls(s: string): string
{
	say("pathurls: "+s);
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

scgirequest(path, scgipath: string, req: ref Req, op: Op, length: int): array of byte
{
	servername := req.h.get("host");
	if(servername == nil)
		servername = op.lhost;
	pathinfo := path[len scgipath:];
	l  :=	("CONTENT_LENGTH",	string length)::
		("GATEWAY_INTERFACE",	"CGI/1.1")::
		("SERVER_PROTOCOL",	http->versionstr(req.version))::
		("SERVER_NAME",		servername)::
		("SCGI",		"1")::
		("REQUEST_METHOD",	http->methodstr(req.method))::
		("REQUEST_URI",		path)::
		("SCRIPT_NAME",		path)::
		("PATH_INFO",		pathinfo)::
		("PATH_TRANSLATED",	pathinfo)::
		("QUERY_STRING",	req.url.query)::
		("SERVER_ADDR",		op.lhost)::
		("SERVER_PORT",		op.lport)::
		("REMOTE_ADDR",		op.rhost)::
		("REMOTE_PORT",		op.rport)::
		environment;
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

suffix(suf, s: string): int
{
	if(len suf > len s)
		return 0;
	return suf == s[len s-len suf:];
}

gettype(path: string): string
{
	for(i := 0; i < len types; i++)
		if(suffix(types[i].t0, path))
			return types[i].t1;
	if(!has(path, '.'))
		return "text/plain; charset=utf-8";
	return "application/octet-stream";
}

days := array[] of {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
months := array[] of {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

httpdate(t: int): string
{
	tm := daytime->gmt(t);
	return sprint("%s, %02d %s %d %02d:%02d:%02d GMT", days[tm.wday], tm.mday, months[tm.mon], tm.year+1900, tm.hour, tm.min, tm.sec);
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

has(s: string, c: int): int
{
	for(i := 0; i < len s; i++)
		if(s[i] == c)
			return 1;
	return 0;
}

rev[T](l: list of T): list of T
{
	r: list of T;
	for(; l != nil; l = tl l)
		r = hd l::r;
	return r;
}

say(s: string)
{
	if(dflag)
		fprint(fildes(2), "%s\n", s);
	if(errorfd != nil)
		fprint(errorfd, "%s\n", s);
}

chat(id: int, s: string)
{
	say(string id+" "+s);
}

die(id: int, s: string)
{
	fail(string id+" "+s);
}

fail(s: string)
{
	fprint(fildes(2), "%s\n", s);
	raise "fail:"+s;
}
