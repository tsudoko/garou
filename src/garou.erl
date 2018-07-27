-module(garou).
-behaviour(ws).
-export([handshake/1, message/2, close/2]). % behaviour(ws)
-export([loop/2, img_loop/3]).              % spawned internally
-export([start/0]).                         % public api

handshake(State) ->
	io:format("got handshake from ~p~n", [State]).

% FIXME: for some reason messages aren't passed here if there's some long running
%        blocking task (e.g. ClearUpdate from client_init/1) until there are more
%        messages sent after it's done, but even then you have a constant "lag"
%
%  poor illustration of the problem
%
%        | -a->        | -> |
%        | -b->        |    | (long running task)
%        | -c->-b->    |    | (still running)
%        |        <-a- | <- |
%        | -c->-b->    |    | (???? the process doesn't receive b even though it's not busy)
%        | -d->-c->-b->| -> |
%        |        <-b- | <- |
%        | -d->-c->    |    | (still stuck)

message(State, {text, <<"new">>}) ->
	ID = erlang:phash2(State),
	?MODULE ! {newclient, State, ID},
	ws:send(State, text, jsx:encode(#{id => ID})),
	client_init(State);
message(State, {text, Msg}) ->
	message_json(State, jsx:decode(Msg)).

close(State, Reason) ->
	?MODULE ! {delconn, State},
	io:format("got close: ~p~n", [Reason]).

gen_name() ->
	gen_name([]).
gen_name(N) when length(N) < 3 ->
	Case = case rand:uniform(2) of 1 -> $a; 2 -> $A end,
	gen_name([rand:uniform($z - $a) + Case|N]);
gen_name(N) ->
	list_to_binary(N).

% TODO (user messages): UndoPoint, Undo, Unban, Fill, Text
% TODO (server replies): clearUpdate, register, unregister, Text, Undo
message_json(S, ID) when is_number(ID) ->
	?MODULE ! {newclient, S, ID},
	client_init(S);
message_json(_, []) ->
	ok;
message_json(S = {_, {_, Path, _}}, [{<<"PLine">>, PLine}|Rest]) ->
	?MODULE ! {getclient, self(), S},
	receive {getclient, S, _, {_, Name}} -> ok end,
	#{<<"X0">> := X0
	 ,<<"X1">> := X1
	 ,<<"Y0">> := Y0
	 ,<<"Y1">> := Y1
	 ,<<"Layer">> := Layer
	 ,<<"Size">> := Size
	 ,<<"R">> := R
	 ,<<"G">> := G
	 ,<<"B">> := B
	 ,<<"A">> := A} = maps:from_list(PLine),
	?MODULE ! {modlayer, Path, Layer, {R, G, B, A}, fun() -> img:line({X0, Y0}, {X1, Y1}, Size) end},
	?MODULE ! {roomsend, Path, #{<<"User">> => Name, <<"PLine">> => PLine}},
	message_json(S, Rest);
message_json(S, [{<<"NameChange">>, Name}|Rest]) ->
	?MODULE ! {getclient, self(), S},
	receive {getclient, S, _, {Admin, PrevName}} -> ok end,
	io:format("[~p] ~p requested name change: ~p~n", [S, PrevName, Name]),
	?MODULE ! {setclient, S, {Admin, Name}},
	ws:send(S, text, jsx:encode(#{<<"NameChange">> => #{from => PrevName, to => Name}})),
	message_json(S, Rest);
message_json(S = {_, {_, Path, _}}, [{<<"Cursor">>, Cursor}|Rest]) ->
	X = proplists:get_value(<<"X">>, Cursor),
	Y = proplists:get_value(<<"Y">>, Cursor),
	?MODULE ! {getclient, self(), S},
	receive {getclient, S, _, {_, Name}} -> ok end,
	?MODULE ! {roomsend, Path, #{<<"User">> => Name, <<"Cursor">> => #{'X' => X, 'Y' => Y}}},
	message_json(S, Rest);
message_json(S, [Msg|Rest]) ->
	io:format("unhandled msg ~p~n", [Msg]),
	message_json(S, Rest).

client_init(S) ->
	?MODULE ! {getclient, self(), S},
	receive {getclient, S, Canvas, Client} -> ok end,
	{N, W, H, _} = Canvas,
	{Admin, Name} = Client,
	ws:send(S, text, jsx:encode(#{canvasSize => #{'N' => N, 'X' => W, 'Y' => H}})),
	if Admin -> ws:send(S, text, jsx:encode(#{admin => Admin})); true -> ok end,
	ws:send(S, text, jsx:encode(#{yourname => Name})),
	send_layers(S, Canvas, 0).
send_layers(S, {N, W, H, [Cur|Rest]}, Num) ->
	Cur ! {get, self()},
	receive {Cur, W, H, Img} -> ok end,
	ws:send(S, text, jsx:encode(#{clearUpdate =>
		#{<<"Clear">> => true
		 ,<<"Layer">> => Num
		 ,<<"Png">> => base64:encode(png:encode(Img, W, H, rgba8))
		 ,'X' => 0
		 ,'Y' => 0}})),
	send_layers(S, {N, W, H, Rest}, Num + 1);
send_layers(_, {_, _, _, []}, _) ->
	ok.

img_loop(W, H, Data) ->
	receive
		{get, Pid} ->
			Pid ! {self(), W, H, Data},
			img_loop(W, H, Data);
		{draw, Color, F} ->
			img_loop(W, H, img:draw(Color, F(), W, H, Data))
	end.

% TODO: maybe look into moving socket-specific state into the socket's
%       controlling process? would remove the need for {getclient, ...}ing
%       on every single message we receive
% do note we'd still need to keep some of it in the main loop since at least
% the name (and admin status?) are persistent between connections

% TODO: do something when loop/2 crashes, would be nice to preserve state
% worst case, kill all clients
loop(Rooms, Connections) ->
	receive
		{newclient, S = {_, {_, Path, _}}, ID} ->
			{Num, W, H} = {2, 1000, 1000},
			{Canvas, Users} = maps:get(Path, Rooms, {{Num, W, H, [spawn(?MODULE, img_loop, [W, H, <<0:(W*H*32)>>]) || _ <- lists:seq(1, Num)]}, #{}}),
			Admin = Users == #{},
			User = maps:get(ID, Users, {Admin, gen_name()}),
			loop(Rooms#{Path => {Canvas, Users#{ID => User}}}, Connections#{S => ID});
		{getclient, Pid, S = {_, {_, Path, _}}} ->
			#{S := ID} = Connections,
			#{Path := {Canvas, #{ID := Client}}} = Rooms,
			Pid ! {getclient, S, Canvas, Client},
			loop(Rooms, Connections);
		{setclient, S = {_, {_, Path, _}}, Client} ->
			#{S := ID} = Connections,
			#{Path := {Canvas, Users}} = Rooms,
			loop(Rooms#{Path => {Canvas, Users#{ID => Client}}}, Connections);
		{modlayer, Path, Layer, Color, F} ->
			#{Path := {{_, _, _, Layers}, _}} = Rooms,
			% lists:nth/2 can crash, we don't handle crashes at all right now
			lists:nth(Layer + 1, Layers) ! {draw, Color, F},
			loop(Rooms, Connections);
		{roomsend, Path, Msg} ->
			[ws:send(S, text, jsx:encode(Msg)) || S = {_, {_, TargetPath, _}} <- maps:keys(Connections), TargetPath == Path],
			loop(Rooms, Connections);
		{delconn, S} ->
			loop(Rooms, maps:remove(S, Connections))
	end.

start() ->
	true = jsx:maps_support(),
	spawn(ws, start, [200, 9393, ?MODULE]),
	Pid = spawn(?MODULE, loop, [#{}, #{}]),
	register(?MODULE, Pid).
