-module(garou).
-behaviour(ws).
-export([handshake/1, message/2, close/2]).
-export([start/0, loop/2]).

handshake(State) ->
	io:format("got handshake from ~p~n", [State]).

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

% TODO (user messages): UndoPoint, Undo, Fill, Text
% TODO (server replies): clearUpdate, admin, register, unregister, Text, Undo
message_json(S, ID) when is_number(ID) ->
	?MODULE ! {newclient, S, ID},
	client_init(S);
message_json(_, []) ->
	ok;
message_json(S, [{<<"PLine">>, PLine}|Rest]) ->
	% TODO: save in canvas, send to other users
	io:format("someone sent a line ~p~n", [PLine]),
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
	{N, X, Y, _} = Canvas,
	{_Admin, Name} = Client,
	ws:send(S, text, jsx:encode(#{canvasSize => #{'N' => N, 'X' => X, 'Y' => Y}})),
	ws:send(S, text, jsx:encode(#{yourname => Name})).

loop(Rooms, Connections) ->
	receive
		{newclient, S = {_, {_, Path, _}}, ID} ->
			{Canvas, Users} = maps:get(Path, Rooms, {{2, 1000, 1000, null}, #{}}),
			User = maps:get(ID, Users, {false, gen_name()}),
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
