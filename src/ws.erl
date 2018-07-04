-module(ws).
-export([start/3, decode_frame/1]).
-export([handshake/2]).

-include_lib("kernel/include/logger.hrl").
-define(WS_GUID, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").

% pedantic TODO (server only):
%  - description (RFC 6455 section [, ([listnumber[#itemnumber|details)]) (how to handle)
%  - handshake URI must be a valid HTTP URI without '#' (3) (7.1.7 fail)
%  - only one CONNECTING connection from a given IP at a time (4.1, 1#2) (???)
%  - handle SNI somehow? (4.1, 1#5 and 4.2.2, #1) (???)
%    - this seems annoying enough to justify not supporting TLS altogether
%      (i.e. offload to some reverse proxy), that would violate 10.6, though
%  - only GETs, only HTTP/1.1 or higher (4.1, 2#2 and 4.2.1, #1) (400)
%  - non-80 (for non-ssl connections)/443 (for ssl connections) ports must be
%    specified explicitly in the Host header (4.1, 2#4) (???)
%  - Upgrade must include "websocket" (4.1, 2#5 and 4.2.1, #3) (400)
%  - Connection must include "Upgrade" (4.1, 2#6 and 4.2.1, #4) (400)
%  - Sec-Websocket-Key must be a base64-encoded 16-byte value (4.1, 2#7 and 4.2.1, #5) (400)
%  - Sec-Websocket-Version must be 13 (4.1, 2#9 and 4.2.1, #6) (400)
%  - the 4 headers mentioned above are required in the handshake
%  - response must be 101, Upgrade=="websocket", Connection=="upgrade", Sec-Websocket-Accept blah (4.2.2 #5)
%  - include sec-websocket-version in 400 responses
%  - storing the origin somewhere might be desirable for later validation (4.2.2 #4)
%    (wouldn't it be better to let a reverse proxy handle this?)
%  - subprotocol support

%  - all frames from the client must be masked (Close with 1002)
%  - all frames from the server must not be masked
%  - unknown opcode -> 7.1.7 fail
%  - limit frame and message size (10.4)

%  - TCP timeouts (inf by default)

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

opcode(Bop = <<0:1, _/bits>>) -> <<Op>> = Bop, {data, opcode_(Op)};
opcode(Bop = <<1:1, _/bits>>) -> <<Op>> = Bop, {control, opcode_(Op)}.
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
	{ok, {Fin, opcode(<<Op>>), undefined, Payload}, Rest};
decode_frame(<<Fin:1, _:3/bits, Op:4, 1:1, 127:7, Len:64, MaskKey:4/bytes, Payload:Len/bytes, Rest/bytes>>) ->
	{ok, {Fin, opcode(<<Op>>), MaskKey, Payload}, Rest};
decode_frame(<<Fin:1, R:3/bits, Op:4, Mask:1, 126:7, Len:16, Rest/bytes>>) ->
	decode_frame(<<Fin:1, R:3/bits, Op:4, Mask:1, 127:7, Len:64, Rest/bytes>>);
decode_frame(<<Fin:1, R:3/bits, Op:4, Mask:1, Len:7, Rest/bytes>>) ->
	decode_frame(<<Fin:1, R:3/bits, Op:4, Mask:1, 127:7, Len:64, Rest/bytes>>);
decode_frame(_) ->
	{more, undefined}.

control_op(S, ping, Data) ->
	gen_tcp:send(S, <<1:1, 0:3, (opcode_to_integer(pong)):4, 0:1, (byte_size(Data)):7, Data/bytes>>);
control_op(_S, pong, _Data) ->
	% TODO: check if pong matches, update last pong?
	ok;
control_op(_S, close, _) ->
	% TODO: close connection
	ok;
control_op(_, _, _) ->
	ok.

handle_data(_, 0, Op, Buf) when Op /= 0 ->
	{Op, Buf};
handle_data(S, 1, Op, Buf) ->
	% TODO: send buf to handler
	{0, <<>>}.

loop_handleframe(Parent, S, _, _, {PrevOp, MsgBuf}, {ok, {Fin, {data, Opcode}, MaskKey, Payload}}) ->
	NewData = unmask(MaskKey, Payload),
	NewOp = case Opcode of 0 -> PrevOp; X -> X end,
	loop(Parent, S, <<>>, handle_data(S, Fin, NewOp, <<MsgBuf, NewData/bytes>>));
loop_handleframe(Parent, S, FrameBuf, NewF, _, {more, _}) ->
	loop(Parent, S, <<FrameBuf/bytes, NewF/bytes>>, {0, <<>>}).

loop(Parent, S, FrameBuf, {PrevOp, MsgBuf}) ->
	case gen_tcp:recv(S, 0, 5000) of
		{ok, NewF} ->
			io:format("received ~p~n", [NewF]),
			% control frames can be sent whenever, even in the middle of
			% a fragmented message, so we need to handle them separately

			% TODO: close if error occurs
			case decode_frame(NewF) of
				{ok, {1, {control, Opcode}, MaskKey, Payload}} ->
					NewData = unmask(MaskKey, Payload),
					control_op(S, Opcode, NewData),
					loop(Parent, S, FrameBuf, {PrevOp, MsgBuf});
				_ ->
					loop_handleframe(Parent, S, FrameBuf, NewF, {PrevOp, MsgBuf}, decode_frame(<<FrameBuf/bytes, NewF/bytes>>))
			end;
		{error, closed} ->
			Parent ! conndied,
			ok;
		{error, E} ->
			?LOG_NOTICE("socket error (recv) ~p~n", [E]),
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
	decode_handshake(S, [{path, Path}], Rest);
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

handshake(Parent, S) ->
	Params = decode_handshake(S),
	% TODO: there can be multiple heeaders with the same name but
	%       different values, concatenate them first somehow
	% Multiple message-header fields with the same field-name MAY be present in a message if and only if the entire field-value for that header field is defined as a comma-separated list [i.e., #(values)]. It MUST be possible to combine the multiple header fields into one "field-name: field-value" pair, without changing the semantics of the message, by appending each subsequent field-value to the first, each separated by a comma.
	true = proplists:is_defined('Host', Params),
	ensure_contains('Connection', Params, "upgrade"),
	ensure_contains('Upgrade', Params, "websocket"),
	"13" = proplists:get_value("Sec-Websocket-Version", Params),
	Key = proplists:get_value("Sec-Websocket-Key", Params),

	% TODO: return 400 if any of the above fails
	gen_tcp:send(S, [<<"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-Websocket-Accept: ">>, sec_websocket_accept(Key), <<"\r\n\r\n">>]),
	% TODO: put 'Host', "Origin" and path somewhere
	loop(Parent, S, <<>>, {0, <<>>}).

srvloop(Maxnum, LSock) ->
	srvloop(Maxnum, LSock, 0).
srvloop(Maxnum, LSock, Maxnum) ->
	receive conndied -> srvloop(Maxnum, LSock, Maxnum - 1) end;
srvloop(Maxnum, LSock, Num) ->
	receive
		conndied -> srvloop(Maxnum, LSock, Num - 1)
	after 0 ->
		case gen_tcp:accept(LSock) of
			{ok, S} ->
				spawn(?MODULE, handshake, [self(), S]),
				srvloop(Maxnum, LSock, Num + 1);
			{error, E} ->
				?LOG_NOTICE("socket error (accept): ~p~n", [E]),
				srvloop(Maxnum, LSock, Num)
		end
	end.

start(Maxnum, LPort, Handler) ->
	case gen_tcp:listen(LPort, [binary, {active, false}]) of
		{ok, LS} ->
			srvloop(Maxnum, LS),
			{ok, Port} = inet:port(LS),
			Port;
		{error, _} = Err ->
			Err
	end.
