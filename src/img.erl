-module(img).
-export([new/2, draw/3, line/2, line/3]).

tsort(A, B) when A > B -> {B, A};
tsort(A, B)            -> {A, B}.

new(W, H) ->
	{?MODULE, W, H, <<0:(W*H*32)>>}.

draw({?MODULE, W, H, Data}, {R, G, B, A}, {X, Y}) when X < W andalso Y < H ->
	Offset = Y*W*4+X*4,
	<<Before:Offset/bytes, _:32, After/bytes>> = Data,
	{?MODULE, W, H, <<Before/bytes, R, G, B, A, After/bytes>>};

draw(Img, Colour, [Cur|Rest]) ->
	draw(draw(Img, Colour, Cur), Colour, Rest);
draw(Img, _, []) ->
	Img.

line_fun({X1, Y1}, {X2, Y2}) ->
	A = (Y2 - Y1) / (X2 - X1),
	B = ((Y1 + Y2) - A * (X1 + X2)) / 2,
	case abs(A) > 1 of
		true  -> {y, fun(Y) -> (Y-B)/A end};
		false -> {x, fun(X) -> A*X+B end}
	end.

line(Start, End) ->
	line(Start, End, 1).
line(Start, End, Thickness) when Thickness =/= 1 ->
	logger:warning("requested unimplemented thickness (~p), falling back to 1", [Thickness]),
	line(Start, End, 1);
line({X, SY}, {X, EY}, _Thickness) ->
	{Y1, Y2} = tsort(SY, EY),
	[{X, round(Y)} || Y <- lists:seq(Y1, Y2)];
line(Start = {SX, SY}, End = {EX, EY}, Thickness) ->
	{Axis, F} = line_fun(Start, End),
	case Axis of
		x ->
			{X1, X2} = tsort(SX, EX),
			[{X, round(F(X))} || X <- lists:seq(X1, X2)];
		y ->
			{Y1, Y2} = tsort(SY, EY),
			[{round(F(Y)), Y} || Y <- lists:seq(Y1, Y2)]
	end.
