-module(pbkdf2).
-export([pbkdf2/3, pbkdf2/4]).

-on_load(init/0).

-define(SHA1_OUTPUT_LENGTH, 20).

init() ->
	SoName = filename:join(
		case code:priv_dir(pbkdf2) of
		    {error, bad_name} ->
		        filename:join(filename:dirname(filename:dirname(code:which(?MODULE))), "priv");
		    Dir ->
		        Dir
		end, atom_to_list(?MODULE)),
	erlang:load_nif(SoName, 0).

pbkdf2(Pass, Salt, Rounds) ->
    pbkdf2(Pass, Salt, Rounds, ?SHA1_OUTPUT_LENGTH).

pbkdf2(_Pass, _Salt, _Rounds, _Length) -> erlang:nif_error(nif_not_loaded).
