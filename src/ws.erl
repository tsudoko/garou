-module(ws).
-export([decode_frame/1]).

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

%  - handle control frames in this module, pass everything else to the custom handler

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

opcode(Op = <<0:1, _:1>>) -> {data, opcode_(Op)};
opcode(Op = <<1:1, _:1>>) -> {control, opcode_(Op)}.
opcode_(1) -> text;
opcode_(2) -> binary;
opcode_(8) -> close;
opcode_(9) -> ping;
opcode_(10) -> pong.

decode_frame(<<_:1, _:3, _:4, 0:1, 127:7, Len:64, P/bytes>>) when byte_size(P) < Len ->
	{more, Len};
decode_frame(<<_:1, _:3, _:4, 1:1, 127:7, Len:64, _:4/bytes, P/bytes>>) when byte_size(P) < Len ->
	{more, Len};
decode_frame(<<Fin:1, Reserved:3/bits, Op:4, 0:1, 127:7, Len:64, Payload/bytes>>) ->
	% TODO ↓: return excess bytes of Payload if byte_size(Payload) > Len
	Len = byte_size(Payload), % TODO: return some error? alternatively move to the pattern above
	{ok, {Fin, opcode(Op), undefined, Payload}, undefined};
decode_frame(<<Fin:1, Reserved:3/bits, Op:4, 1:1, 127:7, Len:64, MaskKey:4/bytes, Payload/bytes>>) ->
	{ok, {Fin, opcode(Op), MaskKey, Payload}, undefined};
decode_frame(<<Fin:1, Reserved:3/bits, Op:4, Mask:1, 126:7, Len:16, Rest/bytes>>) ->
	decode_frame(<<Fin:1, Reserved:3/bits, Op:4, Mask:1, 127:7, Len:64, Rest/bytes>>);
decode_frame(<<Fin:1, Reserved:3/bits, Op:4, Mask:1, Len:7, Rest/bytes>>) ->
	decode_frame(<<Fin:1, Reserved:3/bits, Op:4, Mask:1, 127:7, Len:64, Rest/bytes>>);
decode_frame(_) ->
	{more, undefined}.

decode_message_({more, _}) ->
	{more, undefined};
decode_message_({ok, {Fin, Op, MaskKey, Payload}}) ->
	% TODO: handle multiple frames (fin == 0)
	% maaaybe TODO: unmask here instead of doing it in decode_frame/1,
	%               would preserve frame metadata better too
	ok.

% important details:
%  - An endpoint MUST be capable of handling control frames in the
%    middle of a fragmented message.
%  - As control frames cannot be fragmented, an intermediary MUST NOT
%    attempt to change the fragmentation of a control frame.

% NOTE: If control frames could not be interjected, the latency of a
% ping, for example, would be very long if behind a large message.
% Hence, the requirement of handling control frames in the middle of a
% fragmented message.

listen(Port, WsOpts, ListenOpts) ->
	% WsOpts (all maybe): secure/ssl, resource (path) (or just accept everything and return requested path in accept/n?)
	% ListenOpts: just pass them transparently to gen_tcp:listen/2?
	ok.
