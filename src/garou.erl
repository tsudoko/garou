-module(garou).
-behaviour(ws).
-export([handshake/2, message/2, close/2]).
-export([start/0, loop/2]).

handshake(S, Params) ->
	{_, Path, _} = Params,
	?MODULE ! {newconn, S, Path},
	io:format("got handshake from ~p: ~p~n", [S, Params]).

message(S, {text, "new"}) ->
	ID = integer_to_binary(erlang:phash2(S)),
	?MODULE ! {newclient, S, ID},
	ws:send(S, text, jsx:encode(#{id => ID})),
	client_init(S, ID);
message(S, {text, Msg}) ->
	try
		message_json(S, jsx:decode(Msg))
	catch error:badarg ->
		?MODULE ! {newclient, S, Msg},
		client_init(S, Msg)
	end.

close(S, Reason) ->
	?MODULE ! {delconn, S},
	io:format("got close: ~p~n", [Reason]).

gen_name() ->
	gen_name([]).
gen_name(N) when length(N) < 3 ->
	Case = case rand:uniform(2) of 1 -> $a; 2 -> $A end,
	gen_name([rand:uniform($z - $a) + Case|N]);
gen_name(N) ->
	list_to_binary(N).

% TODO (user messages): UndoPoint, Undo, Fill
% TODO (server replies): clearUpdate, admin, register, unregister, Text, Undo
message_json(_, []) ->
	ok;
message_json(S, [{<<"PLine">>, PLine}|Rest]) ->
	% TODO: save in canvas, send to other users
	io:format("someone sent a line ~p~n", [PLine]),
	message_json(S, Rest);
message_json(S, [{<<"NameChange">>, Name}|Rest]) ->
	% TODO: change name?
	io:format("~p requested a name change: ~p~n", [S, Name]),
	message_json(S, Rest);
message_json(S, [{<<"Cursor">>, _Cursor}|Rest]) ->
	% TODO: send to other users
	message_json(S, Rest);
message_json(S, [Msg|Rest]) ->
	io:format("unhandled msg ~p~n", [Msg]),
	message_json(S, Rest).

client_init(S, ID) ->
	?MODULE ! {getclient, self(), S, ID},
	receive {getclient, ID, Canvas, Client} -> ok end,
	{N, X, Y, _} = Canvas,
	{_Admin, Name} = Client,
	ws:send(S, text, jsx:encode(#{canvasSize => #{'N' => N, 'X' => X, 'Y' => Y}})),
	ws:send(S, text, jsx:encode(#{yourname => Name})).

loop(Rooms, Connections) ->
	receive
		{newconn, S, Path} ->
			loop(Rooms, #{S => Path});
		{newclient, S, ID} ->
			#{S := Path} = Connections,
			{Canvas, Users} = maps:get(Path, Rooms, {{2, 1000, 1000, null}, #{}}),
			User = maps:get(ID, Users, {false, gen_name()}),
			loop(Rooms#{Path => {Canvas, Users#{ID => User}}}, Connections);
		{getclient, Pid, S, ID} ->
			#{S := Path} = Connections, % TODO: you could just keep this state in S, it never changes
			#{Path := {Canvas, #{ID := Client}}} = Rooms,
			Pid ! {getclient, ID, Canvas, Client},
			loop(Rooms, Connections);
		{delconn, S} ->
			loop(Rooms, maps:remove(S, Connections))
	end.

start() ->
	true = jsx:maps_support(),
	spawn(ws, start, [1, 9393, ?MODULE]),
	Pid = spawn(?MODULE, loop, [#{}, #{}]),
	register(?MODULE, Pid).
