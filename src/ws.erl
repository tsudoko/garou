-module(ws).
-export([start/3, send/3]).
-export([handshake/3]).

-callback handshake(State :: tuple()) -> term().
-callback message(State :: tuple(), Message :: tuple()) -> term().
-callback close(State :: tuple(), Reason :: atom() | tuple()) -> term().

-include_lib("kernel/include/logger.hrl").
-define(WS_GUID, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").

% pedantic TODO (server only):
%  - description (RFC 6455 section [, ([listnumber[#itemnumber|details)]) (how to handle)
%  - handshake URI must be a valid HTTP URI without '#' (3) (7.1.7 fail)
%  - only one CONNECTING connection from a given IP at a time (4.1, 1#2) (???)
%  - handle SNI somehow? (4.1, 1#5 and 4.2.2, #1) (???)
%    - this seems annoying enough to justify not supporting TLS altogether
%      (i.e. offload to some reverse proxy), that would violate 10.6, though
%      - providing the .secure/ flag to handlers might be impossible with
%        reverse proxies, though
%  - non-80 (for non-ssl connections)/443 (for ssl connections) ports must be
%    specified explicitly in the Host header (4.1, 2#4) (???)
%  - Sec-Websocket-Key must be a base64-encoded 16-byte value (4.1, 2#7 and 4.2.1, #5) (400)
%  - include sec-websocket-version in 400 responses
%  - parse the Forwarded header (RFC 7239), set secure flag if proto=https
%  - subprotocol support

%  - all frames from the client must be masked (6.1, #5) (Close with 1002)
%  - all frames from the server must not be masked
%  - unknown opcode -> 7.1.7 fail
%  - limit frame and message size (10.4)
%  - reassembled text frames with invalid utf-8 must be Failed (5.6 and 8.1) (1007, 7.1.7)
%  - after decoding the opcode is called a "type", might want to rename some stuff
%  - make some tests?
%    - length field larger than actual length
%    - length field smaller than actual length
%    - binary frames
%    - frames with unrecognized opcodes 
%    - really large frames
%    - really large messages
%    - text frames with non-utf8 data or invalid utf-8
%    - a bunch of invalid handshakes
%    - really large handshake?

sec_websocket_accept(Key) ->
	base64:encode(crypto:hash(sha, [Key, ?WS_GUID])).

unmask(Key, Data) ->
	unmask(Key, Data, <<>>).
unmask(Key, Data, R) when byte_size(Key) =< byte_size(Data) ->
	Keylen = byte_size(Key),
	<<Cur:Keylen/bytes, Rest/bytes>> = Data,
	unmask(Key, Rest, <<R/bytes, (crypto:exor(Cur, Key))/bytes>>);
unmask(Key, Data, R) when byte_size(Key) > byte_size(Data) ->
	Datalen = byte_size(Data),
	<<CutKey:Datalen/bytes, _/bytes>> = Key,
	<<R/bytes, (crypto:exor(Data, CutKey))/bytes>>.

opcode(Bop = <<0:1, _:3>>) -> <<Op:4>> = Bop, {data, opcode_(Op)};
opcode(Bop = <<1:1, _:3>>) -> <<Op:4>> = Bop, {control, opcode_(Op)}.
opcode_(1) -> text;
opcode_(2) -> binary;
opcode_(8) -> close;
opcode_(9) -> ping;
opcode_(10) -> pong.

opcode_to_integer(text) -> 1;
opcode_to_integer(binary) -> 2;
opcode_to_integer(close) -> 8;
opcode_to_integer(ping) -> 9;
opcode_to_integer(pong) -> 10.

decode_frame(<<Fin:1, _:3/bits, Op:4, 0:1, 127:7, Len:64, Payload:Len/bytes, Rest/bytes>>) ->
	{ok, {Fin, opcode(<<Op:4>>), undefined, Payload}, Rest};
decode_frame(<<Fin:1, _:3/bits, Op:4, 1:1, 127:7, Len:64, MaskKey:4/bytes, Payload:Len/bytes, Rest/bytes>>) ->
	{ok, {Fin, opcode(<<Op:4>>), MaskKey, Payload}, Rest};
decode_frame(<<Fin:1, R:3/bits, Op:4, Mask:1, 126:7, Len:16, Rest/bytes>>) ->
	decode_frame(<<Fin:1, R:3/bits, Op:4, Mask:1, 127:7, Len:64, Rest/bytes>>);
decode_frame(<<Fin:1, R:3/bits, Op:4, Mask:1, Len:7, Rest/bytes>>) when Len =< 125 ->
	decode_frame(<<Fin:1, R:3/bits, Op:4, Mask:1, 127:7, Len:64, Rest/bytes>>);
decode_frame(_) ->
	{more, undefined}.

encode_frame(Op, Msg) when byte_size(Msg) =< 125 ->
	<<1:1, 0:3, (opcode_to_integer(Op)):4, 0:1, (byte_size(Msg)):7, Msg/bytes>>;
encode_frame(Op, Msg) when byte_size(Msg) =< 65535 ->
	<<1:1, 0:3, (opcode_to_integer(Op)):4, 0:1, 126:7, (byte_size(Msg)):16, Msg/bytes>>;
encode_frame(Op, Msg) when byte_size(Msg) =< 18446744073709551615 ->
	<<1:1, 0:3, (opcode_to_integer(Op)):4, 0:1, 127:7, (byte_size(Msg)):64, Msg/bytes>>.

status(<<>>) ->
	null;
status(<<Code:16, Data/bytes>>) ->
	{Code, Data}.

handle_control({S, _}, _, ping, Data) ->
	io:format("ping'd (~p)~n", [Data]),
	gen_tcp:send(S, <<1:1, 0:3, (opcode_to_integer(pong)):4, 0:1, (byte_size(Data)):7, Data/bytes>>);
handle_control(_, _, pong, Data) ->
	% TODO: send pings, timeout if there's no pong in time
	io:format("pong get (~p)~n", [Data]);
handle_control(State = {S, _}, Handler, close, Data) ->
	gen_tcp:send(S, encode_frame(close, Data)),
	Handler:close(State, {close, status(Data)});
handle_control(_, _, _, _) ->
	ok.

handle_data(_, _, _Fin = 0, _, _) ->
	ok;
handle_data(_, _, _, control, _) ->
	ok;
handle_data(State, Handler, _Fin = 1, data, Message) ->
	Handler:message(State, Message).

clear_msgbufs(0, Bufs) ->
	Bufs;
clear_msgbufs(1, _) ->
	{0, <<>>}.

send({S, _}, Type, Msg) ->
	gen_tcp:send(S, encode_frame(Type, Msg)).

loop(Parent, State = {S, _}, Handler, {FrameBuf, PrevOp, MsgBuf}) ->
	inet:setopts(S, [{active, once}]),
	receive
		{ws_message, {Op, Msg}} ->
			ok = gen_tcp:send(S, encode_frame(Op, Msg)),
			loop(Parent, State, Handler, {FrameBuf, PrevOp, MsgBuf});
		{tcp, S, Bytes} ->
			NewBuf = <<FrameBuf/bytes, Bytes/bytes>>,
			% TODO: close if decode_frame/1 crashes
			case decode_frame(NewBuf) of
				{ok, {Fin, {T, Opcode}, Key, Payload}, Rest} ->
					Data = unmask(Key, Payload),
					handle_control(State, Handler, Opcode, Data),
					NewOp = case Opcode of 0 -> PrevOp; X -> X end,
					NewMsgBuf = <<MsgBuf/bytes, Data/bytes>>,
					handle_data(State, Handler, Fin, T, {NewOp, NewMsgBuf}),
					{NextOp, NextMsgBuf} = clear_msgbufs(Fin, {NewOp, NewMsgBuf}),
					loop(Parent, State, Handler, {Rest, NextOp, NextMsgBuf});
				{more, _} ->
					loop(Parent, State, Handler, {NewBuf, PrevOp, MsgBuf})
			end;
		{tcp_closed, S} ->
			Handler:close(State, tcp_closed),
			Parent ! conndied,
			ok;
		{tcp_error, S, E} ->
			?LOG_NOTICE("socket error (recv) ~p~n", [E]),
			Handler:close(State, {tcp_error, E}),
			Parent ! conndied,
			ok
	end.

decode_handshake(S) ->
	decode_handshake(S, [], <<>>).
decode_handshake(S, [], <<>>) ->
	% FIXME: this might fail if the path is really long or the packet size is really small
	{ok, Data} = gen_tcp:recv(S, 0),
	{ok, {http_request,
		'GET',
		{abs_path, Path},
		HTTPVer}, Rest} = erlang:decode_packet(http, Data, []),
	decode_handshake(S, [{path, Path}, {http_ver, HTTPVer}], Rest);
decode_handshake(_, Params, <<"\r\n">>) -> % TODO: is it always \r\n?
	Params;
decode_handshake(S, Params, Buf) ->
	case erlang:decode_packet(httph, Buf, []) of
		{ok, {http_header, _, Key, _, Value}, Rest} ->
			decode_handshake(S, [{Key, Value}|Params], Rest);
		{more, _} ->
			{ok, Data} = gen_tcp:recv(S, 0),
			decode_handshake(S, Params, <<Data/bytes, Buf/bytes>>)
	end.

ensure_contains(Key, Proplist, Value) ->
	% FIXME: not exactly right, can give a false positive in e.g.
	%        ensure_contains(1, [{1, "cat"}], "at")
	true = nomatch /= string:find(string:casefold(proplists:get_value(Key, Proplist)), Value).

handshake(Parent, S, Handler) ->
	Params = decode_handshake(S),
	% TODO: there can be multiple heeaders with the same name but
	%       different values, concatenate them first somehow
	% Multiple message-header fields with the same field-name MAY be present
	% in a message if and only if the entire field-value for that header field
	% is defined as a comma-separated list [i.e., #(values)]. It MUST be
	% possible to combine the multiple header fields into one "field-name:
	% field-value" pair, without changing the semantics of the message, by
	% appending each subsequent field-value to the first, each separated by a
	% comma.
	true = proplists:get_value(http_ver, Params) >= {1, 1},
	true = proplists:is_defined('Host', Params),
	ensure_contains('Connection', Params, "upgrade"),
	ensure_contains('Upgrade', Params, "websocket"),
	"13" = proplists:get_value("Sec-Websocket-Version", Params),
	Key = proplists:get_value("Sec-Websocket-Key", Params),

	% TODO: return 400 if any of the above (including decode_handshake/1) fails
	gen_tcp:send(S, [<<"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-Websocket-Accept: ">>, sec_websocket_accept(Key), <<"\r\n\r\n">>]),
	Flags = {
		proplists:get_value('Host', Params),
		proplists:get_value(path, Params),
		proplists:get_value("Origin", Params)
	},
	Handler:handshake({S, Flags}),
	loop(Parent, {S, Flags}, Handler, {<<>>, 0, <<>>}).

srvloop(Maxnum, LSock, Handler) ->
	srvloop_(Maxnum, LSock, Handler, 0).
srvloop_(Maxnum, LSock, Handler, Maxnum) ->
	receive conndied -> srvloop_(Maxnum, LSock, Handler, Maxnum - 1) end;
srvloop_(Maxnum, LSock, Handler, Num) ->
	receive
		conndied -> srvloop(Maxnum, LSock, Num - 1)
	after 0 ->
		case gen_tcp:accept(LSock) of
			{ok, S} ->
				CPid = spawn(?MODULE, handshake, [self(), S, Handler]),
				ok = gen_tcp:controlling_process(S, CPid),
				srvloop_(Maxnum, LSock, Handler, Num + 1);
			{error, E} ->
				?LOG_NOTICE("socket error (accept): ~p~n", [E]),
				srvloop_(Maxnum, LSock, Handler, Num)
		end
	end.

start(Maxnum, LPort, Handler) ->
	case gen_tcp:listen(LPort, [binary, {active, false}]) of
		{ok, LS} ->
			srvloop(Maxnum, LS, Handler),
			{ok, Port} = inet:port(LS),
			Port;
		{error, _} = Err ->
			Err
	end.
