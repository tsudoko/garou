-module(img).
-export([new/2, set_pixel/3, set_pixels/3, line/4, line/5]).

tsort(A, B) when A > B -> {B, A};
tsort(A, B)            -> {A, B}.

new(W, H) ->
	{?MODULE, W, H, <<0:(W*H*32)>>}.

set_pixel({?MODULE, W, H, Data}, {R, G, B, A}, {X, Y}) when X < W andalso Y < H ->
	Offset = Y*W*4+X*4,
	<<Before:Offset/bytes, _:32, After/bytes>> = Data,
	{?MODULE, W, H, <<Before/bytes, R, G, B, A, After/bytes>>}.

set_pixels(Img, Colour, [Cur|Rest]) ->
	set_pixels(set_pixel(Img, Colour, Cur), Colour, Rest);
set_pixels(Img, _, []) ->
	Img.

line_fun({X1, Y1}, {X2, Y2}) ->
	A = (Y2 - Y1) / (X2 - X1),
	B = ((Y1 + Y2) - A * (X1 + X2)) / 2,
	fun(X) -> A*X+B end.

linexy(Start, End) ->
	linexy(Start, End, 1).
linexy(Start, End, Thickness) when Thickness =/= 1 ->
	logger:warning("requested unimplemented thickness (~p), falling back to 1", [Thickness]),
	linexy(Start, End, 1);
linexy({X, SY}, {X, EY}, _Thickness) ->
	{Y1, Y2} = tsort(SY, EY),
	[{X, round(Y)} || Y <- lists:seq(Y1, Y2)];
linexy(Start = {SX, _}, End = {EX, _}, Thickness) ->
	F = line_fun(Start, End),
	{X1, X2} = tsort(SX, EX),
	[{X, round(F(X))} || X <- lists:seq(X1, X2)].

line(Img, Colour, Start, End) ->
	line(Img, Colour, Start, End, 1).
line(Img, Colour, Start, End, Thickness) ->
	set_pixels(Img, Colour, linexy(Start, End, Thickness)).
