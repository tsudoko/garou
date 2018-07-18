-module(png_omake).
-export([akarin/3, kaze/3, ame/3]).

% base: sub
akarin(rgba8, _, <<R, G, B, A, Rest/bytes>>) ->
	akarin_(rgba8, {R, G, B, A}, Rest, <<1, -R, -G, -B, -A>>).
akarin_(rgba8, {PR, PG, PB, PA}, <<R, G, B, A, Rest/bytes>>, Acc) ->
	akarin_(rgba8, {R, G, B, A}, Rest, <<Acc/bytes, (R-PR), (G-PG), (B-PB), (A-PA)>>);
akarin_(rgba8, _, <<>>, Acc) ->
	Acc.

% TODO: add paeth and up versions too!
% another idea: just change the filter id and see what happens (on legit filters too)

% base: sub
kaze(rgba8, _, <<Cur:32/bytes, Rest/bytes>>) ->
	kaze_(rgba8, Rest, <<1, Cur/bytes>>).
kaze_(rgba8, <<R, G, B, A, Rest/bytes>>, Acc) ->
	<<PR, PG, PB, PA>> = binary_part(Acc, {byte_size(Acc), -4}),
	kaze_(rgba8, Rest, <<Acc/bytes, (R-PR), (G-PG), (B-PB), (A-PA)>>);
kaze_(_, <<>>, Acc) ->
	Acc.

% base: average
ame(rgba8, <<UR, UG, UB, UA, Prev/bytes>>, <<R, G, B, A, Rest/bytes>>) ->
	ame_(rgba8, Prev, Rest, <<3,
		(R-floor(UR/2)),
		(G-floor(UG/2)),
		(B-floor(UB/2)),
		(A-floor(UA/2))>>).
ame_(rgba8, <<UR, UG, UB, UA, Prev/bytes>>, <<R, G, B, A, Rest/bytes>>, Acc) ->
	<<PR, PG, PB, PA>> = binary_part(Acc, {byte_size(Acc), -4}),
	ame_(rgba8, Prev, Rest, <<Acc/bytes,
		(R-floor((PR+UR)/2)),
		(G-floor((PG+UG)/2)),
		(B-floor((PB+UB)/2)),
		(A-floor((PA+UA)/2))>>);
ame_(_, <<>>, <<>>, Acc) ->
	Acc.
