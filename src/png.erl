-module(png).
-export([encode/4]).

-define(MAGIC, <<137, 80, 78, 71, 13, 10, 26, 10>>).
-define(INT32MAX, 1 bsl 31 - 1).

% TODO: support multiple IDAT chunks, enforce max chunk size
% maybe TODO: support indexed images too
% m a y b e  TODO: support grayscale images too
% for indexed images: putting transparent colors first allows you to make the transparency chunk smaller
% also tRNS for anything with an alpha channel

chunk(Type) ->
	chunk(Type, <<>>).
chunk(Type, Data) ->
	<<(byte_size(Data)):32,
		Type/bytes,
		Data/bytes,
		(erlang:crc32(<<Type/bytes, Data/bytes>>)):32>>.

filter(none, rgba8, _, <<Data/bytes>>) ->
	<<0, Data/bytes>>;
filter(sub, rgba8, _, <<Cur:32/bytes, Rest/bytes>>) ->
	filter_sub(rgba8, Rest, <<1, Cur/bytes>>);
filter(up, rgba8, Prev, Cur) ->
	filter_up(rgba8, Prev, Cur, <<2>>);
filter(average, rgba8, <<UR, UG, UB, UA, Prev/bytes>>, <<R, G, B, A, Rest/bytes>>) ->
	filter_average(rgba8, Prev, Rest, <<3,
		(R-floor(UR/2)),
		(G-floor(UG/2)),
		(B-floor(UB/2)),
		(A-floor(UA/2))>>);
filter(paeth, rgba8, <<UR, UG, UB, UA, Prev/bytes>>, <<R, G, B, A, Rest/bytes>>) ->
	filter_paeth(rgba8, <<UR, UG, UB, UA, Prev/bytes>>, <<R, G, B, A, Rest/bytes>>, <<4,
		(R-paeth(0, UR, 0)),
		(G-paeth(0, UG, 0)),
		(B-paeth(0, UB, 0)),
		(A-paeth(0, UA, 0))>>).

filter_sub(rgba8, <<R, G, B, A, Rest/bytes>>, Acc) ->
	<<PR, PG, PB, PA>> = binary_part(Acc, {byte_size(Acc), -4}),
	filter_sub(rgba8, Rest, <<Acc/bytes, (R-PR), (G-PG), (B-PB), (A-PA)>>);
filter_sub(_, <<>>, Acc) ->
	Acc.
filter_up(rgba8, <<PR, PG, PB, PA, PRest/bytes>>, <<R, G, B, A, Rest/bytes>>, Acc) ->
	filter_up(rgba8, PRest, Rest, <<Acc/bytes, (R-PR), (G-PG), (B-PB), (A-PA)>>);
filter_up(_, <<>>, <<>>, Acc) ->
	Acc.
filter_average(rgba8, <<UR, UG, UB, UA, Prev/bytes>>, <<R, G, B, A, Rest/bytes>>, Acc) ->
	<<PR, PG, PB, PA>> = binary_part(Acc, {byte_size(Acc), -4}),
	filter_average(rgba8, Prev, Rest, <<Acc/bytes,
		(R-floor((PR+UR)/2)),
		(G-floor((PG+UG)/2)),
		(B-floor((PB+UB)/2)),
		(A-floor((PA+UA)/2))>>);
filter_average(_, <<>>, <<>>, Acc) ->
	Acc.
filter_paeth(rgba8, <<PUR, PUG, PUB, PUA, UR, UG, UB, UA, Prev/bytes>>, <<PR, PG, PB, PA, R, G, B, A, Rest/bytes>>, Acc) ->
	filter_paeth(rgba8, <<UR, UG, UB, UA, Prev/bytes>>, <<R, G, B, A, Rest/bytes>>, <<Acc/bytes,
		(R-paeth(PR, UR, PUR)),
		(G-paeth(PG, UG, PUG)),
		(B-paeth(PB, UB, PUB)),
		(A-paeth(PA, UA, PUA))>>);
filter_paeth(rgba8, <<_:32>>, <<_:32>>, Acc) ->
	Acc.

filter_adaptive(rgba8, Prev, Data) ->
	AbsSignedDiffs = fun
		(<<I/signed, Rest/bytes>>, Cont, Acc) -> Cont(Rest, Cont, [abs(I)|Acc]);
		(<<>>, _, Acc) -> Acc
	end,

	FilterScanlineScore = fun(F, Format, Prev, Data) ->
		Scanline = <<_, Stuff/bytes>> = filter(F, Format, Prev, Data),
		{F, Scanline, lists:sum(AbsSignedDiffs(Stuff, AbsSignedDiffs, []))}
	end,

	_FilterResults = [{_, BestScanline, _}|_] = lists:keysort(3, [FilterScanlineScore(F, rgba8, Prev, Data) || F <- [none, sub, up, average, paeth]]),
	%io:format("~p~n", [[{F, Score} || {F, _, Score} <- FilterResults]]),
	BestScanline.

paeth(Prev, Up, PrevUp) ->
	P = Prev + Up - PrevUp,
	case {abs(P - Prev), abs(P - Up), abs(P - PrevUp)} of
		{Pa, Pb, Pc} when (Pa =< Pb) and (Pa =< Pc) -> Prev;
		{_,  Pb, Pc} when Pb =< Pc -> Up;
		_ -> PrevUp
	end.

idats(rgba8, Bytes, W) ->
	% TODO: split into multiple chunks if needed
	Z = zlib:open(),
	ok = zlib:deflateInit(Z),
	{ok, Chunk} = idat(rgba8, Z, Bytes, W*4),
	Chunk.

% TODO: track size (just add byte_size(C) each iteration?), return {more, IdatChunk, Rest} if chunk size exceeds max size
%       consider setting the max size to something low, it doesn't matter for our use case but it's nicer for decoders since they don't have to keep the whole thing in memory (they need to read the whole chunk first to be able to verify the checksum)
idat(rgba8, Z, Bytes, SSize) ->
	<<Scanline:SSize/bytes, Rest/bytes>> = Bytes,
	C = zlib:deflate(Z, filter(none, rgba8, <<>>, Scanline)),
	idat_(rgba8, Z, <<Scanline/bytes, Rest/bytes>>, SSize, C).
idat_(rgba8, Z, Bytes, SSize, Acc) when byte_size(Bytes) == SSize ->
	C = zlib:deflate(Z, [], finish),
	ok = zlib:deflateEnd(Z),
	zlib:close(Z),
	{ok, chunk(<<"IDAT">>, iolist_to_binary(lists:reverse([C|Acc])))};
idat_(rgba8, Z, Bytes, SSize, Acc) ->
	<<Prev:SSize/bytes, Scanline:SSize/bytes, Rest/bytes>> = Bytes,
	% TODO: adaptive filtering
	C = zlib:deflate(Z, filter_adaptive(rgba8, Prev, Scanline)),
	idat_(rgba8, Z, <<Scanline/bytes, Rest/bytes>>, SSize, [C|Acc]).

encode(Bytes, W, H, rgba8) ->
	BitDepth = 8, ColourType = 6,
	<<?MAGIC/bytes,
		(chunk(<<"IHDR">>, <<W:32, H:32, BitDepth, ColourType, 0, 0, 0>>))/bytes,
		(idats(rgba8, Bytes, W))/bytes,
		(chunk(<<"IEND">>))/bytes>>.
