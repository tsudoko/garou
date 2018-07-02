-define(WS_GUID, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").

sec_websocket_accept(Key) ->
	base64:encode(crypto:hash(sha, [Key, WS_GUID])).
